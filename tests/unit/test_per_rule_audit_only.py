"""Per-rule audit_only behavior (DEC-019).

The policy schema gained `PolicyRule.audit_only` on v1. The field is
optional (None = inherit policy-level). Resolution rules:

  rule.audit_only=True  -> this rule emits events, never enforces
  rule.audit_only=False -> this rule enforces, ignores policy-level audit
  rule.audit_only=None  -> inherit policy.audit_only (default behavior)

Backward compat: a policy without per-rule overrides behaves identically
to the v1 implementation (policy-level audit_only applies to all rules).
"""

from __future__ import annotations

import json
from pathlib import Path

from promptguard.actions import ActionContext, ActionEngine
from promptguard.audit import AuditWriter
from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Category, Policy, PolicyRule


def _det(category: Category, *, start: int = 0, end: int = 10) -> Detection:
    return Detection(
        category=category,
        start=start,
        end=end,
        matched_text="X" * (end - start),
        confidence=0.99,
        detector=f"test:{category.value}",
    )


def _ctx() -> ActionContext:
    return ActionContext(conversation_id="conv-T", request_id="req-T")


# -- backward compatibility ---------------------------------------


def test_policy_level_audit_only_still_works(tmp_path: Path) -> None:
    """v1 behavior: policy.audit_only=True with no per-rule overrides
    behaves like the original audit-only mode."""
    log = tmp_path / "audit.log"
    writer = AuditWriter(log)
    policy = Policy(
        name="legacy",
        audit_only=True,
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
        ],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    text = "x" * 100
    dets = [_det(Category.EMAIL, start=0, end=10), _det(Category.PRIVATE_KEY, start=20, end=30)]
    result = engine.apply(text, dets, _ctx())
    writer.close()
    # Both rules audit-only -> no enforcement
    assert not result.blocked
    assert result.rewritten_text == text
    # Both events emitted
    lines = [line for line in log.read_text().strip().split("\n") if line]
    assert len(lines) == 2


# -- per-rule overrides -------------------------------------------


def test_rule_audit_true_overrides_policy_audit_false(tmp_path: Path) -> None:
    """One rule audits while the rest enforce."""
    log = tmp_path / "audit.log"
    writer = AuditWriter(log)
    policy = Policy(
        name="mixed",
        audit_only=False,
        rules=[
            # Email is audit-only: events emit, no rewrite.
            PolicyRule(category=Category.EMAIL, action=Action.MASK, audit_only=True),
            # Private-key enforces: BLOCK applies normally.
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
        ],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    text = "x" * 100
    # Only the email detection: should NOT block, should NOT rewrite,
    # should emit one audit event.
    dets = [_det(Category.EMAIL, start=0, end=10)]
    result = engine.apply(text, dets, _ctx())
    assert not result.blocked
    assert result.rewritten_text == text
    writer.close()
    lines = [line for line in log.read_text().strip().split("\n") if line]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "email"


def test_rule_audit_false_overrides_policy_audit_true(tmp_path: Path) -> None:
    """One rule enforces while the rest audit."""
    log = tmp_path / "audit.log"
    writer = AuditWriter(log)
    policy = Policy(
        name="opposite",
        audit_only=True,  # default for all rules
        rules=[
            # Email inherits: audit-only.
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            # Private-key explicitly enforces.
            PolicyRule(
                category=Category.PRIVATE_KEY, action=Action.BLOCK, audit_only=False
            ),
        ],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    text = "x" * 100
    dets = [
        _det(Category.EMAIL, start=0, end=10),
        _det(Category.PRIVATE_KEY, start=20, end=30),
    ]
    result = engine.apply(text, dets, _ctx())
    # Private-key enforce path: BLOCK fires.
    assert result.blocked
    writer.close()
    lines = [line for line in log.read_text().strip().split("\n") if line]
    # Email rule emits an audit event even though private-key blocked.
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "email"


def test_mixed_audit_and_enforce_with_mask(tmp_path: Path) -> None:
    """MASK enforces; another category is audit-only on the same request."""
    log = tmp_path / "audit.log"
    writer = AuditWriter(log)
    policy = Policy(
        name="mixed-mask",
        audit_only=False,
        rules=[
            # Email enforces: gets rewritten.
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            # Internal IP is audit-only: emits an event but isn't rewritten.
            PolicyRule(
                category=Category.INTERNAL_IP, action=Action.TOKENIZE, audit_only=True
            ),
        ],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    text = "ping noreply@example.com from 10.0.0.5 please"
    dets = [
        _det(Category.EMAIL, start=5, end=24),
        _det(Category.INTERNAL_IP, start=30, end=38),
    ]
    result = engine.apply(text, dets, _ctx())
    writer.close()
    # Email got masked; internal IP did NOT get tokenized.
    assert "[EMAIL_REDACTED]" in result.rewritten_text
    assert "10.0.0.5" in result.rewritten_text  # not tokenized
    # Audit event emitted only for the audit-only IP rule.
    lines = [line for line in log.read_text().strip().split("\n") if line]
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "internal_ip"
    assert event["would_have_been_action"] == "TOKENIZE"


# -- policy.is_rule_audit_only resolution ---------------------------


def test_policy_resolves_rule_audit_only_with_inheritance() -> None:
    policy = Policy(
        name="r",
        audit_only=True,
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),  # inherit -> True
            PolicyRule(
                category=Category.PRIVATE_KEY, action=Action.BLOCK, audit_only=False
            ),
            PolicyRule(
                category=Category.JWT, action=Action.BLOCK, audit_only=True
            ),
        ],
    )
    assert policy.is_rule_audit_only(Category.EMAIL, 1.0) is True
    assert policy.is_rule_audit_only(Category.PRIVATE_KEY, 1.0) is False
    assert policy.is_rule_audit_only(Category.JWT, 1.0) is True


def test_policy_resolves_audit_only_for_unmatched_category() -> None:
    """No matching rule -> falls back to policy.audit_only (academic
    because the engine drops ALLOW detections from the audit path)."""
    policy_audit_off = Policy(name="off", audit_only=False, rules=[])
    policy_audit_on = Policy(name="on", audit_only=True, rules=[])
    # Use a category with no rule.
    assert policy_audit_off.is_rule_audit_only(Category.EMAIL, 1.0) is False
    assert policy_audit_on.is_rule_audit_only(Category.EMAIL, 1.0) is True
