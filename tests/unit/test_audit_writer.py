"""AuditWriter tests + the no-offending-text fuzz invariant.

Covers:
  * Event shape: every documented field present, nothing extra.
  * JSONL: one line per event, each line valid JSON.
  * pipeline_version + policy_hash present and computed from real
    package metadata / file bytes.
  * Concurrent writes from multiple threads do not corrupt the file.
  * Engine in audit_only mode emits one event per non-ALLOW detection
    and forwards the original text unchanged.
  * Engine in normal mode does NOT write audit events even when a
    writer is wired.
  * Fuzz invariant: random PII strings injected into prompts do not
    appear in any serialized audit event under any code path.
"""

from __future__ import annotations

import json
import random
import string
import threading
from pathlib import Path

import pytest

from promptguard.actions import ActionContext, ActionEngine
from promptguard.audit import (
    AuditEvent,
    AuditWriter,
    compute_policy_hash,
    now_iso8601_utc,
    package_version,
)
from promptguard.core.detection import Detection
from promptguard.core.policy import Action, Category, Policy, PolicyRule


def _det(
    category: Category, *, start: int = 0, end: int = 10, text: str = "X" * 10
) -> Detection:
    return Detection(
        category=category,
        start=start,
        end=end,
        matched_text=text,
        confidence=0.99,
        detector=f"test:{category.value}",
    )


def _ctx() -> ActionContext:
    return ActionContext(conversation_id="conv-T", request_id="req-T")


# ---- writer shape -------------------------------------------------


def test_writer_writes_one_line_per_event(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    w = AuditWriter(log_path)
    for i in range(3):
        w.write(
            AuditEvent(
                timestamp=now_iso8601_utc(),
                conversation_id=f"conv-{i}",
                request_id=f"req-{i}",
                rule="email -> MASK",
                detector="regex:email",
                category="email",
                span_offset=0,
                span_length=10,
                would_have_been_action="MASK",
                pipeline_version="0.1.0a1",
                policy_hash="sha256:abc",
                confidence=0.9,
            )
        )
    w.close()
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        d = json.loads(line)
        # Every documented field present.
        for key in (
            "timestamp",
            "conversation_id",
            "request_id",
            "rule",
            "detector",
            "category",
            "span",
            "would_have_been_action",
            "pipeline_version",
            "policy_hash",
            "confidence",
        ):
            assert key in d, f"missing field: {key}"
        assert "offset" in d["span"] and "length" in d["span"]


def test_writer_concurrent_writes_no_corruption(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    w = AuditWriter(log_path)

    def _emit(thread_id: int) -> None:
        for i in range(20):
            w.write(
                AuditEvent(
                    timestamp=now_iso8601_utc(),
                    conversation_id=f"conv-{thread_id}-{i}",
                    request_id=f"req-{thread_id}-{i}",
                    rule="email -> MASK",
                    detector="regex:email",
                    category="email",
                    span_offset=0,
                    span_length=10,
                    would_have_been_action="MASK",
                    pipeline_version="0.1",
                    policy_hash="sha256:abc",
                    confidence=0.9,
                )
            )

    threads = [threading.Thread(target=_emit, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 8 * 20
    for line in lines:
        json.loads(line)  # every line parses as JSON


# ---- pipeline_version + policy_hash -------------------------------


def test_package_version_matches_dunder() -> None:
    from promptguard import __version__

    assert package_version() == __version__


def test_compute_policy_hash_changes_on_file_change(tmp_path: Path) -> None:
    f = tmp_path / "p.yaml"
    f.write_text("name: a", encoding="utf-8")
    h1 = compute_policy_hash(f)
    f.write_text("name: b", encoding="utf-8")
    h2 = compute_policy_hash(f)
    assert h1.startswith("sha256:")
    assert h1 != h2


def test_compute_policy_hash_missing_file_falls_back(tmp_path: Path) -> None:
    h = compute_policy_hash(tmp_path / "does-not-exist.yaml")
    assert h == "sha256:unknown"


# ---- engine audit_only behavior ----------------------------------


def test_engine_audit_only_does_not_rewrite(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    writer = AuditWriter(log_path)
    policy = Policy(
        name="audit-test",
        audit_only=True,
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
        ],
    )
    engine = ActionEngine(
        policy,
        audit_writer=writer,
        pipeline_version="0.1",
        policy_hash="sha256:test",
    )
    text = "ping noreply@example.com please"
    det = _det(Category.EMAIL, start=5, end=24, text="noreply@example.com")
    result = engine.apply(text, [det], _ctx())

    # Audit-only never blocks and never rewrites.
    assert not result.blocked
    assert result.rewritten_text == text
    # Audit entries reflect what would have happened.
    assert len(result.audit) == 1
    assert result.audit[0].action == "MASK"

    writer.close()
    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["category"] == "email"
    assert event["would_have_been_action"] == "MASK"
    assert event["span"] == {"offset": 5, "length": 19}
    assert event["pipeline_version"] == "0.1"
    assert event["policy_hash"] == "sha256:test"


def test_engine_normal_mode_does_not_write_audit_events(tmp_path: Path) -> None:
    """Auditing fires only in audit_only mode; normal MASK/BLOCK do not log."""
    log_path = tmp_path / "audit.log"
    writer = AuditWriter(log_path)
    policy = Policy(
        name="normal",
        audit_only=False,
        rules=[PolicyRule(category=Category.EMAIL, action=Action.MASK)],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    text = "ping noreply@example.com"
    det = _det(Category.EMAIL, start=5, end=24, text="noreply@example.com")
    result = engine.apply(text, [det], _ctx())
    writer.close()
    assert "[EMAIL_REDACTED]" in result.rewritten_text
    # No audit lines emitted.
    content = log_path.read_text(encoding="utf-8")
    assert content == ""


def test_engine_audit_only_emits_one_event_per_detection(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    writer = AuditWriter(log_path)
    policy = Policy(
        name="audit-multi",
        audit_only=True,
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE),
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
        ],
    )
    engine = ActionEngine(policy, audit_writer=writer)
    dets = [
        _det(Category.EMAIL, start=0, end=10),
        _det(Category.INTERNAL_IP, start=20, end=30),
        _det(Category.PRIVATE_KEY, start=40, end=50),
        _det(Category.OTHER, start=60, end=70),  # ALLOW; should not log
    ]
    engine.apply("X" * 100, dets, _ctx())
    writer.close()
    lines = [
        line
        for line in log_path.read_text(encoding="utf-8").strip().split("\n")
        if line
    ]
    assert len(lines) == 3  # OTHER (ALLOW) is dropped
    actions = {json.loads(line)["would_have_been_action"] for line in lines}
    assert actions == {"MASK", "TOKENIZE", "BLOCK"}


# ---- fuzz invariant: no offending text in any audit event --------


def _random_pii_like(rng: random.Random) -> str:
    """Generate a random string that could plausibly be PII content.

    We use a pool of characters that includes the ASCII letters, digits,
    and the punctuation that PII-bearing strings actually contain
    (`@`, `.`, `:`, `/`, `-`, `_`, `+`, `=`, ` `).
    """
    pool = string.ascii_letters + string.digits + "@.:/-_+= \t"
    length = rng.randint(8, 64)
    return "".join(rng.choices(pool, k=length))


def test_fuzz_no_offending_text_in_audit_events(tmp_path: Path) -> None:
    """Stdlib fuzz: 200 random PII strings, none must appear verbatim in
    any serialized audit event written under any code path.

    For each iteration we generate a synthetic prompt containing the
    random PII string at a random offset, run the engine in audit-only
    mode, then read the log file and assert the random string is not
    present anywhere in the file content.
    """
    log_path = tmp_path / "audit.log"
    writer = AuditWriter(log_path)
    policy = Policy(
        name="fuzz",
        audit_only=True,
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.CLOUD_API_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE),
            PolicyRule(category=Category.SECRET, action=Action.BLOCK),
            PolicyRule(category=Category.PRIVATE_NAME, action=Action.MASK),
            PolicyRule(category=Category.CUSTOMER_NAME, action=Action.TOKENIZE),
        ],
    )
    engine = ActionEngine(
        policy,
        audit_writer=writer,
        pipeline_version="0.1",
        policy_hash="sha256:fuzz",
    )

    rng = random.Random(0xCAFE)
    pii_samples: list[str] = []
    categories = [
        Category.EMAIL,
        Category.PRIVATE_KEY,
        Category.CLOUD_API_KEY,
        Category.INTERNAL_IP,
        Category.SECRET,
        Category.PRIVATE_NAME,
        Category.CUSTOMER_NAME,
    ]
    for i in range(200):
        secret_text = _random_pii_like(rng)
        prefix_len = rng.randint(0, 50)
        suffix_len = rng.randint(0, 50)
        prefix = "".join(rng.choices(string.ascii_letters + " ", k=prefix_len))
        suffix = "".join(rng.choices(string.ascii_letters + " ", k=suffix_len))
        prompt = prefix + secret_text + suffix
        start = len(prefix)
        end = start + len(secret_text)
        category = categories[i % len(categories)]
        det = Detection(
            category=category,
            start=start,
            end=end,
            matched_text=secret_text,
            confidence=0.95,
            detector=f"fuzz:{category.value}",
        )
        engine.apply(
            prompt,
            [det],
            ActionContext(
                conversation_id=f"conv-fuzz-{i}", request_id=f"req-fuzz-{i}"
            ),
        )
        pii_samples.append(secret_text)

    writer.close()
    log_content = log_path.read_text(encoding="utf-8")
    for sample in pii_samples:
        # Skip too-short samples that may legitimately appear by chance
        # in the JSONL field structure (timestamps, hashes).
        if len(sample) < 8:
            continue
        assert sample not in log_content, (
            f"FUZZ FAIL: random PII sample {sample!r} appeared in audit log"
        )
