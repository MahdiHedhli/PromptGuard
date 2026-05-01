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
    """Each conversation issues independent random tokens (DEC-012)."""
    import re as _re

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
    # Each conversation issued exactly one token of the expected shape.
    pattern = _re.compile(r"\[INTERNAL_IP_[a-f0-9]{16,}\]")
    assert len(a_tokens) == 1 and len(b_tokens) == 1
    a_token = next(iter(a_tokens))
    b_token = next(iter(b_tokens))
    assert pattern.fullmatch(a_token), a_token
    assert pattern.fullmatch(b_token), b_token
    # The two random suffixes must differ (DEC-012 unguessability promise).
    assert a_token != b_token
    # Each map only records its own original.
    assert a_tokens[a_token] == "10.0.0.1"
    assert b_tokens[b_token] == "10.0.0.1"
    # Conversation B's restorer must not surface conversation A's mapping.
    assert shared_map.lookup("B", a_token) is None
    assert shared_map.lookup("A", b_token) is None


def test_tokenize_reverse_path_round_trips_known_token() -> None:
    """Reverse path substitutes back tokens issued in the same conversation."""
    tm = TokenMap()
    token = tm.issue("conv", Category.EMAIL, "x@example.com")
    out = tm.restore("conv", f"the answer is {token} etc.")
    assert out == "the answer is x@example.com etc."


def test_tokenize_reverse_path_passes_unknown_tokens_through() -> None:
    """Tokens not in this conversation's map must NOT be substituted.

    Defensive against threat-model A7: an LLM could emit a token that
    looks like ours, but if we did not issue it for this conversation we
    must not invent a mapping.
    """
    tm = TokenMap()
    tm.issue("convA", Category.EMAIL, "alice@example.com")
    out = tm.restore("convB", "ping [EMAIL_a3f9c1d2e4b56789] please")
    assert out == "ping [EMAIL_a3f9c1d2e4b56789] please"


def test_tokenize_idempotent_within_conversation() -> None:
    """Re-tokenizing the same value in the same conversation returns the same token."""
    tm = TokenMap()
    a = tm.issue("conv", Category.EMAIL, "x@example.com")
    b = tm.issue("conv", Category.EMAIL, "x@example.com")
    assert a == b


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


def test_identical_spans_from_two_detectors_dedupe(
) -> None:
    """When two detectors emit IDENTICAL (start, end, category) spans
    (e.g. regex AND presidio both flag the same IP), the rewrite must
    produce one substitution, not two. DEC-023.

    Two-substitution behavior corrupted the wire (the second sub's
    text[end:] index referred to the post-first-sub text, splicing
    the second token onto the middle of the first token).
    """
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE)],
    )
    engine = ActionEngine(policy)
    text = "host is 10.0.0.5 today"
    # Two detections at the same span from two detector sources.
    det_regex = _det(Category.INTERNAL_IP, start=8, end=16, text="10.0.0.5")
    det_presidio = Detection(
        category=Category.INTERNAL_IP,
        start=8,
        end=16,
        matched_text="10.0.0.5",
        confidence=0.95,
        detector="presidio:IP_ADDRESS",
    )
    result = engine.apply(text, [det_regex, det_presidio], _ctx())
    # Exactly one TOKENIZE substitution; rewritten text contains the
    # token once and not corrupt suffix-splice patterns like
    # "[INTERNAL_IP_xxx]xxx]".
    import re as _re

    tokens = _re.findall(r"\[INTERNAL_IP_[a-f0-9]{16,}\]", result.rewritten_text)
    assert len(tokens) == 1, (
        f"expected 1 token, got {len(tokens)} in {result.rewritten_text!r}"
    )
    # No corrupt-splice pattern.
    assert "]IP_" not in result.rewritten_text, (
        f"DEC-023 corruption pattern in output: {result.rewritten_text!r}"
    )
    # Original IP gone.
    assert "10.0.0.5" not in result.rewritten_text


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
