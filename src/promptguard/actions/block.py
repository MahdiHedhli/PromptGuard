"""BLOCK action.

Collects every detection it owns into a list of `Violation` entries.
The text is returned unchanged because BLOCK never rewrites; the engine
will short-circuit and refuse to forward the request.
"""

from __future__ import annotations

from promptguard.actions.base import (
    Action,
    ActionContext,
    ActionResult,
    AuditEntry,
    Violation,
)
from promptguard.core.detection import Detection


class BlockAction(Action):
    name: str = "BLOCK"

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> ActionResult:
        if not detections:
            return ActionResult(text=text)
        violations = tuple(
            Violation(
                category=d.category.value,
                detector=d.detector,
                confidence=d.confidence,
            )
            for d in detections
        )
        audit = tuple(
            AuditEntry(
                category=d.category.value,
                detector=d.detector,
                action=self.name,
                start=d.start,
                end=d.end,
                confidence=d.confidence,
                replacement="",
            )
            for d in detections
        )
        return ActionResult(text=text, audit=audit, violations=violations)
