"""Action interface.

An `Action` consumes a payload (text + the detections that fired against it)
and returns an `ActionResult`. Each action owns its own rewrite semantics,
so the engine can dispatch detections grouped by action.

Design rationale (DEC-008): a single Action class per action type, instead
of per-detection branching inside one engine, keeps each rewrite path
testable in isolation. BLOCK can collect violations and never touch the
text. MASK substitutes by category. TOKENIZE substitutes per-occurrence
and updates the token map. The engine glues them together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from promptguard.core.detection import Detection


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One row of the per-request audit trail.

    Fields are intentionally string-typed for easy JSONification and so the
    audit log shape is identical regardless of detector. `replacement` is
    the static tag (MASK) or the issued token (TOKENIZE). For BLOCK it is
    the empty string because BLOCK never rewrites.
    """

    category: str
    detector: str
    action: str
    start: int
    end: int
    confidence: float
    replacement: str


@dataclass(frozen=True, slots=True)
class Violation:
    """A single BLOCK-triggering detection, surfaced in the error envelope.

    The `matched_text` is deliberately omitted: the threat model says the
    error response must not echo the offending text. Operators correlate
    via the request ID and their own audit log.
    """

    category: str
    detector: str
    confidence: float


@dataclass(slots=True)
class ActionContext:
    """Per-request mutable state passed through the engine.

    `conversation_id` scopes TOKENIZE so the same email in two distinct
    conversations gets distinct tokens and distinct map entries. `request_id`
    is what we cite in the BLOCK error envelope for audit correlation.
    """

    conversation_id: str
    request_id: str


@dataclass(frozen=True, slots=True)
class ActionResult:
    """Output of one Action over a slice of detections.

    `text` is the rewritten payload. For BLOCK this equals the input (BLOCK
    does not rewrite). `audit` is appended to the request's audit log.
    `violations` is non-empty only for BLOCK.
    """

    text: str
    audit: tuple[AuditEntry, ...] = field(default_factory=tuple)
    violations: tuple[Violation, ...] = field(default_factory=tuple)


class Action(Protocol):
    """An action takes (text, detections, context) and returns an ActionResult.

    Detections passed to `apply` are pre-filtered by the engine to only the
    spans this action owns. Actions do not see detections destined for other
    actions; that's the engine's responsibility.
    """

    name: str

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> ActionResult: ...
