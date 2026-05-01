"""Action engine: dispatches detections to actions per policy.

Order of operations:

  1. Group detections by the action chosen for their category.
  2. If any detection maps to BLOCK, run BLOCK first and return blocked
     immediately. Other detections are still recorded in the audit so
     operators can see what else was in the prompt; they do not get
     rewritten because the request never leaves the host.
  3. Otherwise, apply MASK and TOKENIZE in a single right-to-left pass
     over the union of their spans. Both actions rewrite by span, so
     interleaving is safe.

Idempotency: re-applying the engine to already-rewritten text is a no-op
because mask tags ([EMAIL_REDACTED]) and token tags ([EMAIL_001]) do
not match any detector regex. We test this explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from promptguard.actions.base import (
    ActionContext,
    AuditEntry,
    Violation,
)
from promptguard.actions.block import BlockAction
from promptguard.actions.mask import MaskAction
from promptguard.actions.tokenize import TokenizeAction, TokenMap
from promptguard.audit import AuditEvent, AuditWriter, now_iso8601_utc
from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Policy


@dataclass(frozen=True, slots=True)
class EngineResult:
    """Aggregate result of running the engine over a payload."""

    blocked: bool
    rewritten_text: str
    audit: tuple[AuditEntry, ...] = field(default_factory=tuple)
    violations: tuple[Violation, ...] = field(default_factory=tuple)
    policy_name: str = ""
    policy_version: str = ""


class ActionEngine:
    def __init__(
        self,
        policy: Policy,
        token_map: TokenMap | None = None,
        *,
        audit_writer: AuditWriter | None = None,
        pipeline_version: str = "",
        policy_hash: str = "",
    ) -> None:
        self._policy = policy
        self._token_map = token_map or TokenMap()
        self._block = BlockAction()
        self._mask = MaskAction()
        self._tokenize = TokenizeAction(self._token_map)
        self._audit_writer = audit_writer
        self._pipeline_version = pipeline_version
        self._policy_hash = policy_hash

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def token_map(self) -> TokenMap:
        return self._token_map

    @property
    def audit_writer(self) -> AuditWriter | None:
        return self._audit_writer

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> EngineResult:
        # Bucket detections into six buckets: action x {enforce, audit}.
        # Per-rule audit_only (DEC-019) overrides policy-level audit_only.
        # Detections whose category resolves to ALLOW are dropped: they
        # are not violations, not rewrites, and do not pollute the audit.
        bucket_block_enforce: list[Detection] = []
        bucket_block_audit: list[Detection] = []
        bucket_mask_enforce: list[Detection] = []
        bucket_mask_audit: list[Detection] = []
        bucket_tokenize_enforce: list[Detection] = []
        bucket_tokenize_audit: list[Detection] = []
        for d in detections:
            action = self._policy.action_for(d.category, d.confidence)
            if action == Action.ALLOW:
                continue
            audit_only = self._policy.is_rule_audit_only(d.category, d.confidence)
            if action == Action.BLOCK:
                (bucket_block_audit if audit_only else bucket_block_enforce).append(d)
            elif action == Action.MASK:
                (bucket_mask_audit if audit_only else bucket_mask_enforce).append(d)
            elif action == Action.TOKENIZE:
                (bucket_tokenize_audit if audit_only else bucket_tokenize_enforce).append(d)

        # Emit audit events for every audit-only detection regardless of
        # whether enforcement also fires. Operator workflow: "audit-only
        # this one rule for two weeks then promote" needs the events to
        # accumulate even on requests that other rules block.
        self._emit_audit_events(bucket_block_audit, BlockAction.name, context)
        self._emit_audit_events(bucket_mask_audit, MaskAction.name, context)
        self._emit_audit_events(bucket_tokenize_audit, TokenizeAction.name, context)

        bucket_block = bucket_block_enforce
        bucket_mask = bucket_mask_enforce
        bucket_tokenize = bucket_tokenize_enforce

        if bucket_block:
            block_result = self._block.apply(text, bucket_block, context)
            audit_entries = list(block_result.audit) + self._audit_entries_for(
                bucket_block_audit + bucket_mask_audit + bucket_tokenize_audit
            )
            return EngineResult(
                blocked=True,
                rewritten_text=text,
                audit=tuple(audit_entries),
                violations=block_result.violations,
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )

        # No BLOCKs: rewrite. MASK and TOKENIZE both rewrite by span; we
        # apply each action's rewrite, but combine into a single ordered
        # pass so overlapping spans of different actions don't double-substitute.
        all_rewrites: list[tuple[Detection, str]] = []
        # MASK substitutions are static; TOKENIZE substitutions issue tokens.
        # We compute substitutions lazily for TOKENIZE so we can reuse the
        # same per-conversation token across detectors that match the same
        # original value.
        from promptguard.actions.mask import mask_tag_for

        for d in bucket_mask:
            all_rewrites.append((d, mask_tag_for(d.category)))
        for d in bucket_tokenize:
            original = text[d.start : d.end]
            token = self._token_map.issue(
                conversation_id=context.conversation_id,
                category=d.category,
                original=original,
            )
            all_rewrites.append((d, token))

        # When two spans overlap (e.g. a JWT also matches the secret category),
        # the longer span wins; the inner one is dropped before rewrite. This
        # is right because a JWT replaced as a single token reads more cleanly
        # than a JWT with its middle masked out as a separate secret span.
        kept = _select_outer_spans(all_rewrites)
        # Right-to-left so earlier offsets stay valid as we rewrite.
        kept.sort(key=lambda dr: -dr[0].start)
        rewritten = text
        audit: list[AuditEntry] = []
        for d, replacement in kept:
            rewritten = rewritten[: d.start] + replacement + rewritten[d.end :]
            audit.append(
                AuditEntry(
                    category=d.category.value,
                    detector=d.detector,
                    action=(
                        MaskAction.name if d in bucket_mask else TokenizeAction.name
                    ),
                    start=d.start,
                    end=d.end,
                    confidence=d.confidence,
                    replacement=replacement,
                )
            )
        audit.reverse()

        # Append the audit-only detections to the audit trail so callers
        # see what fired without enforcement.
        audit.extend(
            self._audit_entries_for(
                bucket_block_audit + bucket_mask_audit + bucket_tokenize_audit
            )
        )
        return EngineResult(
            blocked=False,
            rewritten_text=rewritten,
            audit=tuple(audit),
            violations=(),
            policy_name=self._policy.name,
            policy_version=self._policy.version,
        )

    def _audit_entries_for(self, detections: list[Detection]) -> list[AuditEntry]:
        """Build AuditEntry rows for audit-only detections (no rewrite)."""
        from promptguard.core.policy import Action  # already imported above

        entries: list[AuditEntry] = []
        for d in detections:
            action = self._policy.action_for(d.category, d.confidence)
            entries.append(
                AuditEntry(
                    category=d.category.value,
                    detector=d.detector,
                    action=action.value,
                    start=d.start,
                    end=d.end,
                    confidence=d.confidence,
                    replacement="",
                )
            )
        return entries

    def _emit_audit_events(
        self,
        detections: list[Detection],
        action_name: str,
        context: ActionContext,
    ) -> None:
        if self._audit_writer is None:
            return
        for d in detections:
            self._audit_writer.write(
                AuditEvent(
                    timestamp=now_iso8601_utc(),
                    conversation_id=context.conversation_id,
                    request_id=context.request_id,
                    rule=f"{d.category.value} -> {action_name}",
                    detector=d.detector,
                    category=d.category.value,
                    span_offset=d.start,
                    span_length=d.end - d.start,
                    would_have_been_action=action_name,
                    pipeline_version=self._pipeline_version,
                    policy_hash=self._policy_hash,
                    confidence=round(d.confidence, 4),
                )
            )

    def _apply_audit_only(
        self,
        text: str,
        bucket_block: list[Detection],
        bucket_mask: list[Detection],
        bucket_tokenize: list[Detection],
        context: ActionContext,
    ) -> EngineResult:
        """Audit-only path: compute decisions, emit events, do not rewrite.

        The text returned equals the input text. `blocked` is always
        False (audit-only never blocks). The audit log gets one event
        per non-ALLOW detection, with `would_have_been_action` recording
        what the engine would have done.
        """
        audit_entries: list[AuditEntry] = []
        for buckets, action_name in (
            (bucket_block, BlockAction.name),
            (bucket_mask, MaskAction.name),
            (bucket_tokenize, TokenizeAction.name),
        ):
            for d in buckets:
                audit_entries.append(
                    AuditEntry(
                        category=d.category.value,
                        detector=d.detector,
                        action=action_name,
                        start=d.start,
                        end=d.end,
                        confidence=d.confidence,
                        replacement="",
                    )
                )
                if self._audit_writer is not None:
                    self._audit_writer.write(
                        AuditEvent(
                            timestamp=now_iso8601_utc(),
                            conversation_id=context.conversation_id,
                            request_id=context.request_id,
                            rule=f"{d.category.value} -> {action_name}",
                            detector=d.detector,
                            category=d.category.value,
                            span_offset=d.start,
                            span_length=d.end - d.start,
                            would_have_been_action=action_name,
                            pipeline_version=self._pipeline_version,
                            policy_hash=self._policy_hash,
                            confidence=round(d.confidence, 4),
                        )
                    )
        return EngineResult(
            blocked=False,
            rewritten_text=text,
            audit=tuple(audit_entries),
            violations=(),
            policy_name=self._policy.name,
            policy_version=self._policy.version,
        )


def _select_outer_spans(
    rewrites: list[tuple[Detection, str]],
) -> list[tuple[Detection, str]]:
    """Pick a non-overlapping subset of spans: longest-first, drop any
    span that overlaps an already-kept one (DEC-023).

    Two spans overlap iff `a.start < b.end and b.start < a.end`. Sequential
    text-mutation rewrite (right-to-left) only produces correct output when
    spans are disjoint; any overlap (identical, contained, or partial)
    causes the second substitution's text-slice indices to refer to the
    already-mutated text, splicing one substitution onto the middle of
    another. The visible bug surfaced when regex and presidio both flagged
    the same IP, and again when OPF emitted two adjacent spans for a
    single email.

    Selection: sort by (length DESC, confidence DESC), then iterate keeping
    a span only if it does not overlap any already-kept span. This:
      * preserves the existing "outer span wins" behavior (the longest
        span is processed first; anything contained inside it overlaps
        and gets dropped);
      * deduplicates identical or near-identical detections from multiple
        detector layers (the first one in sort order is kept, the others
        overlap with it and are dropped);
      * gracefully handles the "two adjacent fragments from one detector"
        pathology by keeping the longest contiguous span available, even
        if that means dropping shorter adjacent fragments.
    """
    sorted_rewrites = sorted(
        rewrites,
        key=lambda dr: (-(dr[0].end - dr[0].start), -dr[0].confidence),
    )
    kept: list[tuple[Detection, str]] = []
    for d, replacement in sorted_rewrites:
        overlap = False
        for k_d, _ in kept:
            if k_d.start < d.end and d.start < k_d.end:
                overlap = True
                break
        if not overlap:
            kept.append((d, replacement))
    return kept
