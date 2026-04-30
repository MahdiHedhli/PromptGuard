"""Post-call hook unit tests.

Validates the reverse path through the LiteLLM hook surface:
  * non-streaming: response object's text fields get tokens substituted back
  * streaming iterator: each chunk's strings get substituted in place
  * conversation isolation: a request without our metadata is a no-op
  * conversation isolation: tokens from convo A do not leak into convo B
"""

from __future__ import annotations

from typing import Any

from promptguard.actions import ActionContext, ActionEngine
from promptguard.actions.tokenize import TokenMap
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Action, Category, Policy, PolicyRule
from promptguard.detectors.regex_detector import RegexDetector
from promptguard.proxy.litellm_hooks import PromptGuardHook


def _hook(token_map: TokenMap | None = None) -> PromptGuardHook:
    policy = Policy(
        name="t",
        rules=[PolicyRule(category=Category.EMAIL, action=Action.TOKENIZE)],
    )
    pipeline = DetectionPipeline([RegexDetector()])
    engine = ActionEngine(policy, token_map=token_map)
    return PromptGuardHook(policy=policy, pipeline=pipeline, engine=engine)


# ---- non-streaming reverse path -----------------------------------


async def test_post_call_success_restores_anthropic_response_text() -> None:
    hook = _hook()
    # Issue a token through the engine so the conversation map exists.
    token = hook.token_map.issue("conv-X", Category.EMAIL, "alice@example.com")
    # Anthropic-shaped response with content blocks.
    response: dict[str, Any] = {
        "id": "msg_abc",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": f"Sure, I'll email {token} now."},
            {"type": "text", "text": "Anything else?"},
        ],
    }
    request_data: dict[str, Any] = {"metadata": {"conversation_id": "conv-X"}}
    out = await hook.async_post_call_success_hook(request_data, None, response)
    assert out["content"][0]["text"] == "Sure, I'll email alice@example.com now."
    assert out["content"][1]["text"] == "Anything else?"


async def test_post_call_success_no_metadata_is_passthrough() -> None:
    """If pre-call did not run (no conversation metadata), do nothing."""
    hook = _hook()
    response: dict[str, Any] = {"content": [{"type": "text", "text": "no map exists"}]}
    out = await hook.async_post_call_success_hook({}, None, response)
    assert out["content"][0]["text"] == "no map exists"


async def test_post_call_success_unknown_token_passes_through() -> None:
    hook = _hook()
    hook.token_map.issue("conv-X", Category.EMAIL, "alice@example.com")
    response: dict[str, Any] = {
        "content": [
            {"type": "text", "text": "claim from convo Y: [EMAIL_a3f9c1d2e4b56789]"},
        ]
    }
    request_data: dict[str, Any] = {"metadata": {"conversation_id": "conv-X"}}
    out = await hook.async_post_call_success_hook(request_data, None, response)
    # Unknown token must NOT be substituted (defensive A7 mitigation).
    assert "[EMAIL_a3f9c1d2e4b56789]" in out["content"][0]["text"]
    assert "alice" not in out["content"][0]["text"]


async def test_post_call_success_walks_pydantic_like_objects() -> None:
    """Mimic LiteLLM's typed response shape (object with __dict__)."""

    class FakeContent:
        def __init__(self, text: str) -> None:
            self.type = "text"
            self.text = text

    class FakeResponse:
        def __init__(self, content: list[FakeContent]) -> None:
            self.id = "msg_abc"
            self.role = "assistant"
            self.content = content

    hook = _hook()
    tok = hook.token_map.issue("conv-X", Category.EMAIL, "alice@example.com")
    resp = FakeResponse([FakeContent(f"reach {tok} please")])
    request_data: dict[str, Any] = {"metadata": {"conversation_id": "conv-X"}}
    out = await hook.async_post_call_success_hook(request_data, None, resp)
    assert out.content[0].text == "reach alice@example.com please"


# ---- streaming iterator reverse path ------------------------------


async def test_post_call_streaming_iterator_substitutes_per_chunk() -> None:
    hook = _hook()
    tok = hook.token_map.issue("conv-X", Category.EMAIL, "alice@example.com")

    async def _upstream():
        # Each chunk is a dict mimicking ModelResponseStream shape.
        yield {"choices": [{"delta": {"content": f"Hi {tok},"}}]}
        yield {"choices": [{"delta": {"content": " how are"}}]}
        yield {"choices": [{"delta": {"content": f" you {tok}?"}}]}

    request_data = {"metadata": {"conversation_id": "conv-X"}}

    out_chunks = []
    async for chunk in hook.async_post_call_streaming_iterator_hook(
        None, _upstream(), request_data
    ):
        out_chunks.append(chunk["choices"][0]["delta"]["content"])
    assert "".join(out_chunks) == "Hi alice@example.com, how are you alice@example.com?"


async def test_post_call_streaming_iterator_no_metadata_is_passthrough() -> None:
    hook = _hook()

    async def _upstream():
        yield {"choices": [{"delta": {"content": "[EMAIL_a3f9c1d2e4b56789]"}}]}

    out_chunks = []
    async for chunk in hook.async_post_call_streaming_iterator_hook(
        None, _upstream(), {}
    ):
        out_chunks.append(chunk["choices"][0]["delta"]["content"])
    assert "".join(out_chunks) == "[EMAIL_a3f9c1d2e4b56789]"


async def test_post_call_streaming_iterator_isolates_conversations() -> None:
    """Token from convo A must not be restored when convo B is streaming."""
    hook = _hook()
    tok_a = hook.token_map.issue("convA", Category.EMAIL, "alice@example.com")

    async def _upstream():
        yield {"choices": [{"delta": {"content": f"reach {tok_a}"}}]}

    request_data = {"metadata": {"conversation_id": "convB"}}
    out_chunks = []
    async for chunk in hook.async_post_call_streaming_iterator_hook(
        None, _upstream(), request_data
    ):
        out_chunks.append(chunk["choices"][0]["delta"]["content"])
    assert tok_a in "".join(out_chunks)
    assert "alice" not in "".join(out_chunks)
