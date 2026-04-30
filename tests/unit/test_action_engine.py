from __future__ import annotations

from promptguard.actions import ActionEngine
from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Category, Policy, PolicyRule


def _det(category: Category, *, confidence: float = 0.99) -> Detection:
    return Detection(
        category=category,
        start=0,
        end=10,
        matched_text="X" * 10,
        confidence=confidence,
        detector="test",
    )


def test_action_engine_block_short_circuits_to_blocked_outcome() -> None:
    policy = Policy(
        name="t",
        rules=[
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
        ],
    )
    engine = ActionEngine(policy)
    outcome = engine.decide([_det(Category.PRIVATE_KEY), _det(Category.EMAIL)])
    assert outcome.blocked
    assert outcome.block_reason is not None
    actions = {d.detection.category: d.action for d in outcome.decisions}
    assert actions[Category.PRIVATE_KEY] == Action.BLOCK
    assert actions[Category.EMAIL] == Action.MASK


def test_action_engine_no_block_when_only_mask_or_tokenize() -> None:
    policy = Policy(
        name="t",
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.DOMAIN, action=Action.TOKENIZE),
        ],
    )
    engine = ActionEngine(policy)
    outcome = engine.decide([_det(Category.EMAIL), _det(Category.DOMAIN)])
    assert not outcome.blocked
    assert outcome.block_reason is None


def test_action_engine_allows_uncategorized() -> None:
    policy = Policy(name="t", rules=[])
    engine = ActionEngine(policy)
    outcome = engine.decide([_det(Category.EMAIL)])
    assert not outcome.blocked
    assert outcome.decisions[0].action == Action.ALLOW
