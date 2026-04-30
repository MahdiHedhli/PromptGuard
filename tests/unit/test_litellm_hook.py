"""LiteLLM hook unit tests.

Validates JSON safety: detection runs across joined message strings but
substitutions go back into the right paths without disturbing the envelope.
Also confirms the BLOCK path raises with the expected envelope.
"""

from __future__ import annotations

from typing import Any

import pytest

from promptguard.actions import ActionEngine
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Action, Category, Policy, PolicyRule
from promptguard.detectors.regex_detector import RegexDetector
from promptguard.proxy.litellm_hooks import BlockedByPolicy, PromptGuardHook


def _hook(policy: Policy) -> PromptGuardHook:
    pipeline = DetectionPipeline([RegexDetector()])
    return PromptGuardHook(policy=policy, pipeline=pipeline, engine=ActionEngine(policy))


def _default_policy() -> Policy:
    return Policy(
        name="default",
        rules=[
            PolicyRule(category=Category.PRIVATE_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.CLOUD_API_KEY, action=Action.BLOCK),
            PolicyRule(category=Category.DATABASE_URL, action=Action.BLOCK),
            PolicyRule(category=Category.JWT, action=Action.BLOCK),
            PolicyRule(category=Category.EMAIL, action=Action.MASK),
            PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE),
        ],
    )


# ---- JSON safety ---------------------------------------------------------


async def test_hook_rewrites_string_content_in_anthropic_messages_shape() -> None:
    """messages[i].content as a plain string."""
    body = {
        "model": "claude-sonnet-4-6",
        "messages": [
            {"role": "user", "content": "ping me at noreply@example.com"},
            {"role": "assistant", "content": "ok"},
        ],
        "max_tokens": 100,
    }
    rewritten = await _hook(_default_policy())._inspect(body)
    assert rewritten["messages"][0]["content"] == "ping me at [EMAIL_REDACTED]"
    # Untouched fields must be byte-identical.
    assert rewritten["model"] == "claude-sonnet-4-6"
    assert rewritten["max_tokens"] == 100
    assert rewritten["messages"][1]["content"] == "ok"


async def test_hook_rewrites_anthropic_content_blocks() -> None:
    """messages[i].content as a list of {type:text, text:...} blocks."""
    import re as _re

    body = {
        "model": "claude-opus-4-7",
        "system": "you are helpful",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "host is 10.0.0.5 and"},
                    {"type": "text", "text": "user is alice@example.com"},
                ],
            }
        ],
    }
    rewritten = await _hook(_default_policy())._inspect(body)
    blocks = rewritten["messages"][0]["content"]
    # Internal IP is TOKENIZE in default policy; token format is DEC-012.
    assert _re.fullmatch(
        r"host is \[INTERNAL_IP_[a-f0-9]{16,}\] and", blocks[0]["text"]
    ), blocks[0]["text"]
    assert blocks[1]["text"] == "user is [EMAIL_REDACTED]"
    # Block types preserved
    assert blocks[0]["type"] == "text"
    assert blocks[1]["type"] == "text"


async def test_hook_rewrites_nested_tool_result_text() -> None:
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "tu_1",
                        "content": [
                            {"type": "text", "text": "the user typed bob@x.com"},
                        ],
                    }
                ],
            }
        ]
    }
    rewritten = await _hook(_default_policy())._inspect(body)
    nested = rewritten["messages"][0]["content"][0]["content"][0]["text"]
    assert nested == "the user typed [EMAIL_REDACTED]"


async def test_hook_blocks_on_credentials_and_does_not_leak_text() -> None:
    body = {
        "messages": [
            {
                "role": "user",
                "content": "deploy with key AKIAIOSFODNN7EXAMPLE please",
            }
        ]
    }
    with pytest.raises(BlockedByPolicy) as exc_info:
        await _hook(_default_policy())._inspect(body)
    env = exc_info.value.envelope
    assert env["type"] == "error"
    assert "cloud_api_key" in env["error"]["promptguard"]["categories"]
    # The AWS key must not appear anywhere in the envelope.
    import json

    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(env)


async def test_hook_does_not_disturb_envelope_keys() -> None:
    """Top-level body keys we don't inspect must come back unchanged."""
    body: dict[str, Any] = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "temperature": 0.7,
        "stream": False,
        "metadata": {"conversation_id": "conv-A"},
        "tool_choice": {"type": "auto"},
        "messages": [{"role": "user", "content": "hello"}],
    }
    before = {k: v for k, v in body.items() if k != "messages"}
    out = await _hook(_default_policy())._inspect(body)
    after = {k: v for k, v in out.items() if k != "messages"}
    assert before == after


async def test_hook_idempotent_on_already_rewritten_body() -> None:
    """Running the hook twice must not double-substitute."""
    body = {"messages": [{"role": "user", "content": "ping me at a@b.com"}]}
    once = await _hook(_default_policy())._inspect(body)
    once_text = once["messages"][0]["content"]
    twice = await _hook(_default_policy())._inspect(once)
    assert twice["messages"][0]["content"] == once_text


async def test_hook_no_inspectable_strings_returns_body_unchanged() -> None:
    body: dict[str, Any] = {"model": "gpt-4o-mini", "metadata": {"x": 1}}
    out = await _hook(_default_policy())._inspect(body)
    assert out is body
