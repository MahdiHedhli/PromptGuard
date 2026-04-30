"""ConversationTokenMap unit tests.

Covers:
  * Token format and uniqueness (DEC-012).
  * Idempotency within a conversation.
  * Conversation isolation (no cross-leak).
  * Reverse path passes unknown tokens through (defensive).
  * TTL eviction.
  * LRU eviction at max conversations.
  * Concurrent issue + restore under the lock.
"""

from __future__ import annotations

import re
import threading
import time

import pytest

from promptguard.actions.tokenize import (
    DEFAULT_MAX_CONVERSATIONS,
    DEFAULT_TTL_SECONDS,
    TokenMap,
    find_tokens,
    is_token_string,
)
from promptguard.core.policy import Category

TOKEN_PATTERN = re.compile(r"\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]")


# -- token format ---------------------------------------------------


def test_token_format_matches_dec_012() -> None:
    tm = TokenMap()
    token = tm.issue("c", Category.EMAIL, "x@example.com")
    assert TOKEN_PATTERN.fullmatch(token), token
    # Specifically 16 hex chars (lower bound).
    suffix = token.split("_")[-1].rstrip("]")
    assert len(suffix) >= 16
    assert all(c in "0123456789abcdef" for c in suffix)


def test_token_uniqueness_across_distinct_originals() -> None:
    tm = TokenMap()
    a = tm.issue("c", Category.EMAIL, "alice@example.com")
    b = tm.issue("c", Category.EMAIL, "bob@example.com")
    assert a != b


def test_is_token_string_and_find_tokens() -> None:
    """Helpers used by the streaming restorer."""
    assert is_token_string("[EMAIL_a3f9c1d2e4b56789]")
    assert not is_token_string("[EMAIL_abc]")  # too short
    assert not is_token_string("[email_a3f9c1d2e4b56789]")  # lowercase category
    assert not is_token_string("prefix [EMAIL_a3f9c1d2e4b56789] suffix")
    matches = find_tokens(
        "Two: [EMAIL_a3f9c1d2e4b56789] and [INTERNAL_IP_4b8e1a92cd3f7e60]."
    )
    assert len(matches) == 2


# -- idempotency ----------------------------------------------------


def test_idempotent_within_conversation() -> None:
    tm = TokenMap()
    a = tm.issue("c", Category.EMAIL, "x@example.com")
    b = tm.issue("c", Category.EMAIL, "x@example.com")
    assert a == b


def test_distinct_conversations_get_distinct_tokens() -> None:
    """Two convos can hold the same original; tokens MUST differ (DEC-012)."""
    tm = TokenMap()
    a = tm.issue("convA", Category.EMAIL, "x@example.com")
    b = tm.issue("convB", Category.EMAIL, "x@example.com")
    assert a != b


# -- reverse path semantics ----------------------------------------


def test_reverse_path_substitutes_known_tokens() -> None:
    tm = TokenMap()
    tok_e = tm.issue("c", Category.EMAIL, "x@example.com")
    tok_ip = tm.issue("c", Category.INTERNAL_IP, "10.0.0.5")
    out = tm.restore("c", f"hi {tok_e} from {tok_ip} please")
    assert out == "hi x@example.com from 10.0.0.5 please"


def test_reverse_path_does_not_invent_mappings() -> None:
    """Unknown tokens (not in this conversation) pass through unchanged."""
    tm = TokenMap()
    tm.issue("convA", Category.EMAIL, "alice@example.com")
    fake = "[EMAIL_a3f9c1d2e4b56789]"
    out = tm.restore("convB", f"ping {fake}")
    assert out == f"ping {fake}"


def test_reverse_path_empty_text_is_passthrough() -> None:
    tm = TokenMap()
    tm.issue("c", Category.EMAIL, "x@example.com")
    assert tm.restore("c", "") == ""
    assert tm.restore("c", "no tokens here") == "no tokens here"


def test_reverse_path_unknown_conversation_passthrough() -> None:
    tm = TokenMap()
    tm.issue("convA", Category.EMAIL, "x@example.com")
    assert tm.restore("never-seen-conv", "anything") == "anything"


def test_lookup_returns_none_for_unknown() -> None:
    tm = TokenMap()
    tm.issue("c", Category.EMAIL, "x@example.com")
    assert tm.lookup("c", "[EMAIL_deadbeef00112233]") is None
    assert tm.lookup("not-a-conv", "[EMAIL_a3f9c1d2e4b56789]") is None


# -- TTL eviction ---------------------------------------------------


def test_ttl_evicts_idle_conversations(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_now = [1000.0]

    def _mono() -> float:
        return fake_now[0]

    import promptguard.actions.tokenize as tokmod

    monkeypatch.setattr(tokmod.time, "monotonic", _mono)

    tm = TokenMap(max_conversations=10, ttl_seconds=60)
    tm.issue("convA", Category.EMAIL, "x@example.com")
    fake_now[0] += 30
    assert tm.lookup("convA", "[EMAIL_doesnotexist000000]") is None  # touches LRU
    assert tm.conversation_count() == 1

    # Advance past TTL.
    fake_now[0] += 200
    assert tm.conversation_count() == 0
    # Issuing into an evicted conversation creates a fresh state with a
    # new random token; old token is gone forever.
    new_token = tm.issue("convA", Category.EMAIL, "x@example.com")
    assert TOKEN_PATTERN.fullmatch(new_token)


# -- LRU eviction ---------------------------------------------------


def test_lru_evicts_oldest_when_over_max() -> None:
    tm = TokenMap(max_conversations=3, ttl_seconds=3600)
    tm.issue("A", Category.EMAIL, "a@x")
    time.sleep(0.001)
    tm.issue("B", Category.EMAIL, "b@x")
    time.sleep(0.001)
    tm.issue("C", Category.EMAIL, "c@x")
    time.sleep(0.001)
    # Touching A should refresh it so the next eviction drops B.
    tm.lookup("A", "[EMAIL_anything000000000]")
    time.sleep(0.001)
    tm.issue("D", Category.EMAIL, "d@x")
    # B was the oldest unaccessed; it should be gone.
    assert tm.lookup("B", "[EMAIL_anything000000000]") is None
    assert tm.issued_tokens("A") != {}
    assert tm.issued_tokens("C") != {}
    assert tm.issued_tokens("D") != {}


# -- concurrency ----------------------------------------------------


def test_concurrent_issue_and_restore_no_corruption() -> None:
    tm = TokenMap()
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=2.0)
            for j in range(50):
                cid = f"c{i % 4}"
                original = f"user{i}_{j}@example.com"
                token = tm.issue(cid, Category.EMAIL, original)
                assert TOKEN_PATTERN.fullmatch(token)
                # Round-trip must work even under contention.
                out = tm.restore(cid, f"hi {token}")
                assert out == f"hi {original}"
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


# -- defaults reflect DEC-013 --------------------------------------


def test_defaults_match_dec_013() -> None:
    assert DEFAULT_TTL_SECONDS == 3600
    assert DEFAULT_MAX_CONVERSATIONS == 100
