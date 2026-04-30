"""Action engine stub.

Day 1 ships a minimal decision pass: take a list of detections + a policy,
report what would happen. The actual rewriter (MASK / TOKENIZE) lands in
Day 2-4 per the roadmap.

The shape is deliberately frozen now so detectors and the proxy can be
written against a stable contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Policy


@dataclass(frozen=True, slots=True)
class ActionDecision:
    """The action chosen for a single detection."""

    detection: Detection
    action: Action


@dataclass(frozen=True, slots=True)
class ActionOutcome:
    """The aggregate result of running the action engine over a payload."""

    blocked: bool
    decisions: tuple[ActionDecision, ...] = field(default_factory=tuple)
    rewritten_text: str | None = None
    block_reason: str | None = None


class ActionEngine:
    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def decide(self, detections: list[Detection]) -> ActionOutcome:
        """Day 1: report decisions; do not yet rewrite or tokenize.

        Day 2 fills in the rewrite path and BLOCK error responses.
        """
        decisions: list[ActionDecision] = []
        block_reason: str | None = None
        for d in detections:
            action = self._policy.action_for(d.category, d.confidence)
            decisions.append(ActionDecision(detection=d, action=action))
            if action == Action.BLOCK and block_reason is None:
                block_reason = (
                    f"category={d.category.value} matched by {d.detector} "
                    f"at [{d.start},{d.end})"
                )
        return ActionOutcome(
            blocked=block_reason is not None,
            decisions=tuple(decisions),
            rewritten_text=None,
            block_reason=block_reason,
        )
