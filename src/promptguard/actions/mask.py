"""MASK action.

Replaces each detected span with a static, category-derived tag like
`[EMAIL_REDACTED]`. The original value is dropped, no token map is kept.
This is the right action for any data class where the existence of a
reversal ledger is itself a contractual or regulatory liability
(threat-model A6).

MASK is one-way and idempotent: a tag like `[EMAIL_REDACTED]` does not
match any detector, so re-running the engine on already-masked text is
a no-op. We rely on detector regexes not matching their own output.
"""

from __future__ import annotations

from promptguard.actions.base import Action, ActionContext, ActionResult, AuditEntry
from promptguard.core.detection import Detection
from promptguard.core.policy import Category


def mask_tag_for(category: Category) -> str:
    return f"[{category.value.upper()}_REDACTED]"


class MaskAction(Action):
    name: str = "MASK"

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> ActionResult:
        if not detections:
            return ActionResult(text=text)
        new_text, audit = _substitute(text, detections, self.name)
        return ActionResult(text=new_text, audit=audit)


def _substitute(
    text: str,
    detections: list[Detection],
    action_name: str,
) -> tuple[str, tuple[AuditEntry, ...]]:
    # Walk detections right-to-left so earlier offsets stay valid as we
    # rewrite. Sort by start descending; ties broken by larger span first
    # so an outer span wins over an inner overlap.
    ordered = sorted(detections, key=lambda d: (-d.start, -(d.end - d.start)))
    audit: list[AuditEntry] = []
    out = text
    last_start = len(text) + 1
    for d in ordered:
        if d.end > last_start:
            # Overlapping with a span we already rewrote. Skip; the outer
            # rewrite already covered this region.
            continue
        replacement = mask_tag_for(d.category)
        out = out[: d.start] + replacement + out[d.end :]
        audit.append(
            AuditEntry(
                category=d.category.value,
                detector=d.detector,
                action=action_name,
                start=d.start,
                end=d.end,
                confidence=d.confidence,
                replacement=replacement,
            )
        )
        last_start = d.start
    audit.reverse()
    return out, tuple(audit)
