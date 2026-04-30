from __future__ import annotations

from promptguard.actions import ActionContext, ActionEngine, TokenMap, mask_tag_for
from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Category, Policy, PolicyRule


def _det(
    category: Category,
    *,
    start: int = 0,
    end: int = 10,
    text: str = "X" * 10,
    confidence: float = 0.99,
    detector: str = "test",
) -> Detection:
    return Detection(
        category=category,
        start=start,
        end=end,
        matched_text=text,
        confidence=confidence,
        detector=detector,
    )


def _ctx() -> ActionContext:
    return ActionContext(conversation_id="conv-test", request_id="req-test")


# ----------------- BLOCK ---------------------------------------------------


def test_block_short_circuits_and_does_not_rewrite() -> None:
    policy = Policy(
        name="t",
        rules=[
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
        ],
    )
    engine = ActionEngine(policy)
    text = "key XXXXXXXXXX and email YYYYYYYYYY"
    detections = [
        _det(Category.PRIVATE_KEY, start=4, end=14, text=text[4:14]),
        _det(Category.EMAIL, start=25, end=35, text=text[25:35]),
    ]
    result = engine.apply(text, detections, _ctx())
    assert result.blocked
    assert result.rewritten_text == text  # BLOCK never rewrites.
    cats = {v.category for v in result.violations}
    assert "private_key" in cats
    # Audit only carries BLOCK rows when blocked; the secondary MASK is
    # not applied because the request is rejected.
    assert {a.category for a in result.audit} == {"private_key"}
    assert result.policy_name == "t"


# ----------------- MASK ---------------------------------------------------


def test_mask_substitutes_static_tag() -> None:
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.EMAIL, action=Action.MASK)],
    )
    engine = ActionEngine(policy)
    text = "hi noreply@example.com bye"
    det = _det(Category.EMAIL, start=3, end=22, text="noreply@example.com")
    result = engine.apply(text, [det], _ctx())
    assert not result.blocked
    assert result.rewritten_text == f"hi {mask_tag_for(Category.EMAIL)} bye"
    assert result.audit[0].replacement == mask_tag_for(Category.EMAIL)
    assert result.audit[0].action == "MASK"


def test_mask_is_idempotent_on_retag() -> None:
    """Re-running the engine on already-masked text must be a no-op."""
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.EMAIL, action=Action.MASK)],
    )
    engine = ActionEngine(policy)
    text = f"hi {mask_tag_for(Category.EMAIL)} bye"
    # No detections (the tag does not match the email regex).
    result = engine.apply(text, [], _ctx())
    assert result.rewritten_text == text


# ----------------- TOKENIZE -----------------------------------------------


def test_tokenize_issues_unique_tokens_per_original() -> None:
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE)],
    )
    engine = ActionEngine(policy)
    text = "first 10.0.0.1 then 10.0.0.2 again 10.0.0.1"
    dets = [
        _det(Category.INTERNAL_IP, start=6, end=14, text="10.0.0.1"),
        _det(Category.INTERNAL_IP, start=20, end=28, text="10.0.0.2"),
        _det(Category.INTERNAL_IP, start=35, end=43, text="10.0.0.1"),
    ]
    result = engine.apply(text, dets, _ctx())
    # Same original re-uses its token; distinct originals get distinct tokens.
    issued = engine.token_map.issued_tokens("conv-test")
    assert set(issued.values()) == {"10.0.0.1", "10.0.0.2"}
    # Tokens substituted in place; original IPs no longer in text.
    assert "10.0.0.1" not in result.rewritten_text
    assert "10.0.0.2" not in result.rewritten_text
    # Three substitutions in audit, all TOKENIZE.
    assert {a.action for a in result.audit} == {"TOKENIZE"}
    assert len(result.audit) == 3


def test_tokenize_per_conversation_isolation() -> None:
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE)],
    )
    shared_map = TokenMap()
    engine = ActionEngine(policy, token_map=shared_map)
    text = "host 10.0.0.1"
    det = _det(Category.INTERNAL_IP, start=5, end=13, text="10.0.0.1")
    engine.apply(text, [det], ActionContext(conversation_id="A", request_id="r1"))
    engine.apply(text, [det], ActionContext(conversation_id="B", request_id="r2"))
    a_tokens = shared_map.issued_tokens("A")
    b_tokens = shared_map.issued_tokens("B")
    # Both conversations issued their own [INTERNAL_IP_001].
    assert list(a_tokens.keys()) == ["[INTERNAL_IP_001]"]
    assert list(b_tokens.keys()) == ["[INTERNAL_IP_001]"]
    # And each map only records its own.
    assert a_tokens != {} and b_tokens != {}
    assert a_tokens["[INTERNAL_IP_001]"] == "10.0.0.1"


def test_tokenize_reverse_path_is_identity_at_v1() -> None:
    """v1 ships the reverse path stubbed; Day 3-4 will replace this test."""
    tm = TokenMap()
    tm.issue("conv", Category.EMAIL, "x@example.com")
    out = tm.restore("conv", "the answer is [EMAIL_001] etc.")
    assert out == "the answer is [EMAIL_001] etc."


# ----------------- ALLOW + bucketing --------------------------------------


def test_allow_for_uncategorized_does_not_pollute_audit_or_rewrite() -> None:
    policy = Policy(name="t", rules=[])  # everything ALLOW
    engine = ActionEngine(policy)
    text = "hi noreply@example.com bye"
    det = _det(Category.EMAIL, start=3, end=22, text="noreply@example.com")
    result = engine.apply(text, [det], _ctx())
    assert not result.blocked
    assert result.rewritten_text == text
    assert result.audit == ()


def test_overlapping_spans_outer_wins() -> None:
    """A JWT also matches the secret category. The outer (longer) span wins."""
    policy = Policy(
        name="t",
        rules=[
            PolicyRule(category=Category.JWT, action=Action.MASK),
            PolicyRule(category=Category.SECRET, action=Action.MASK),
        ],
    )
    engine = ActionEngine(policy)
    text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature123"
    jwt = _det(Category.JWT, start=7, end=58, text=text[7:58])
    secret = _det(Category.SECRET, start=20, end=40, text=text[20:40])
    result = engine.apply(text, [jwt, secret], _ctx())
    # The JWT is masked once; the inner secret detection is dropped because
    # its span is contained within the already-rewritten JWT region.
    assert result.rewritten_text.count(mask_tag_for(Category.JWT)) == 1
    assert mask_tag_for(Category.SECRET) not in result.rewritten_text
