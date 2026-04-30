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
    def __init__(self, policy: Policy, token_map: TokenMap | None = None) -> None:
        self._policy = policy
        self._token_map = token_map or TokenMap()
        self._block = BlockAction()
        self._mask = MaskAction()
        self._tokenize = TokenizeAction(self._token_map)

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def token_map(self) -> TokenMap:
        return self._token_map

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> EngineResult:
        # Bucket detections by the action our policy chooses for them.
        # Detections whose category resolves to ALLOW are dropped: they
        # are not violations, not rewrites, and do not pollute the audit.
        bucket_block: list[Detection] = []
        bucket_mask: list[Detection] = []
        bucket_tokenize: list[Detection] = []
        for d in detections:
            action = self._policy.action_for(d.category, d.confidence)
            if action == Action.BLOCK:
                bucket_block.append(d)
            elif action == Action.MASK:
                bucket_mask.append(d)
            elif action == Action.TOKENIZE:
                bucket_tokenize.append(d)
            # ALLOW falls through; not recorded.

        if bucket_block:
            block_result = self._block.apply(text, bucket_block, context)
            return EngineResult(
                blocked=True,
                rewritten_text=text,
                audit=block_result.audit,
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

        return EngineResult(
            blocked=False,
            rewritten_text=rewritten,
            audit=tuple(audit),
            violations=(),
            policy_name=self._policy.name,
            policy_version=self._policy.version,
        )


def _select_outer_spans(
    rewrites: list[tuple[Detection, str]],
) -> list[tuple[Detection, str]]:
    """Drop spans that are contained inside another span; keep the outer.

    Two spans (a_start, a_end) and (b_start, b_end) "contain" b in a iff
    a_start <= b_start and a_end >= b_end and (a_start, a_end) != (b_start, b_end).
    Identical spans are kept once (first occurrence wins).
    """
    sorted_rewrites = sorted(
        rewrites,
        key=lambda dr: (dr[0].start, -(dr[0].end - dr[0].start)),
    )
    kept: list[tuple[Detection, str]] = []
    for d, replacement in sorted_rewrites:
        contained = False
        for k_d, _ in kept:
            if (
                k_d.start <= d.start
                and k_d.end >= d.end
                and (k_d.start, k_d.end) != (d.start, d.end)
            ):
                contained = True
                break
        if not contained:
            kept.append((d, replacement))
    return kept
