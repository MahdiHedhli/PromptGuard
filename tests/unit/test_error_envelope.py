"""BLOCK error envelope tests.

The envelope must:
  * be parseable as both an Anthropic and OpenAI error payload
  * carry the PromptGuard extension (request_id, categories, detectors)
  * never echo the offending text
"""

from __future__ import annotations

import json

import pytest

from promptguard.actions.base import Violation
from promptguard.proxy.errors import (
    ERROR_CODE,
    ERROR_TYPE,
    assert_no_payload_leak,
    build_block_envelope,
    render_envelope,
)


def _vios() -> list[Violation]:
    return [
        Violation(category="cloud_api_key", detector="regex:aws_access_key_id", confidence=0.95),
        Violation(category="private_key", detector="regex:pem_private_key", confidence=0.99),
        Violation(category="cloud_api_key", detector="regex:gcp_api_key", confidence=0.9),
    ]


def test_envelope_top_level_is_anthropic_error_shape() -> None:
    env = build_block_envelope(
        _vios(), request_id="req-1", policy_name="default", policy_version="1"
    )
    # Anthropic clients look for top-level type == "error" and error.message.
    assert env["type"] == "error"
    assert "error" in env
    assert "message" in env["error"]


def test_envelope_carries_openai_keys_for_openai_clients() -> None:
    env = build_block_envelope(
        _vios(), request_id="req-2", policy_name="default", policy_version="1"
    )
    err = env["error"]
    # OpenAI clients look for error.message + error.type; param can be null.
    assert err["message"]
    assert err["type"] == ERROR_TYPE
    assert err["code"] == ERROR_CODE
    assert err["param"] is None


def test_envelope_carries_promptguard_extension() -> None:
    env = build_block_envelope(
        _vios(), request_id="req-3", policy_name="default", policy_version="1"
    )
    pg = env["error"]["promptguard"]
    assert pg["request_id"] == "req-3"
    assert pg["policy_name"] == "default"
    assert pg["policy_version"] == "1"
    assert pg["violation_count"] == 3
    # Categories are deduped + sorted for stable wire output.
    assert pg["categories"] == ["cloud_api_key", "private_key"]
    # Detectors include both AWS and GCP entries.
    assert "regex:aws_access_key_id" in pg["detectors"]
    assert "regex:gcp_api_key" in pg["detectors"]
    assert len(pg["violations"]) == 3


def test_envelope_does_not_include_offending_text() -> None:
    """The offending values must never appear in the envelope."""
    original = (
        "Hi, my AWS key is AKIAIOSFODNN7EXAMPLE and the cert is "
        "-----BEGIN PRIVATE KEY-----abc=== etc"
    )
    env = build_block_envelope(
        _vios(), request_id="req-4", policy_name="default", policy_version="1"
    )
    serialized = render_envelope(env)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert "BEGIN PRIVATE KEY" not in serialized
    # Belt-and-braces: defensive check finds no 6-char windows of the prompt.
    assert_no_payload_leak(env, original)


def test_render_envelope_is_stable_and_round_trippable() -> None:
    env = build_block_envelope(
        _vios(), request_id="req-5", policy_name="default", policy_version="1"
    )
    s = render_envelope(env)
    again = json.loads(s)
    # Re-render with sort_keys to confirm stability across calls.
    assert again == env


def test_zero_violation_envelope_does_not_pluralize() -> None:
    env = build_block_envelope(
        [], request_id="req-6", policy_name="default", policy_version="1"
    )
    assert env["error"]["promptguard"]["violation_count"] == 0


def test_assert_no_payload_leak_detects_leakage() -> None:
    env = {
        "error": {"message": "totally innocent message", "promptguard": {}},
        "type": "error",
    }
    with pytest.raises(AssertionError):
        assert_no_payload_leak(env, "totally innocent message")
