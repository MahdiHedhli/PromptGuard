"""Mock Anthropic /v1/messages upstream for end-to-end TOKENIZE testing.

Behavior: parses the incoming request, finds any token-shaped substrings
(`[CATEGORY_<16+hex>]`) in the user message, and returns a non-streaming
response that echoes those tokens back. This simulates an LLM that
"reasons about" tokenized content: the proxy's outbound rewrite gave
the upstream a token, the upstream returns the same token in its reply,
and the proxy's reverse path must substitute the original value back so
the user sees the round-trip.

This mock is for integration testing only. It accepts any auth header
and never makes an outbound call. Run inside the compose stack and
point LiteLLM at it via `api_base`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

logger = logging.getLogger("promptguard.mock_anthropic")

app = FastAPI(title="PromptGuard Mock Anthropic", version="0.1.0a1")

_TOKEN_RE = re.compile(r"\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]")


class MessagesRequest(BaseModel):
    model: str
    max_tokens: int = 100
    messages: list[dict[str, Any]]
    system: Any | None = None
    stream: bool = False


def _collect_user_text(req: MessagesRequest) -> str:
    """Walk the request and return all user-facing text concatenated."""
    parts: list[str] = []
    for msg in req.messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
    return "\n".join(parts)


def _build_reply_text(user_text: str) -> str:
    """Echo any tokens found in the user text plus a confirmation phrase.

    Specifically: if the user text contains tokens, we say
    "Confirmed: <token1>, <token2>." If no tokens, we say "Confirmed: clean."
    The point is to give the proxy a deterministic response that lets
    the test assert the round-trip restored the original value(s).
    """
    tokens = _TOKEN_RE.findall(user_text)
    if not tokens:
        return "Confirmed: clean."
    return "Confirmed token echo: " + ", ".join(tokens) + "."


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


_LAST_RECEIVED: dict[str, Any] = {"user_text": None, "tokens_seen": [], "stream": False}


@app.get("/_test/last_received")
def last_received() -> dict[str, Any]:
    """Test-only introspection: what did the upstream most recently see?"""
    return _LAST_RECEIVED


@app.post("/v1/messages")
async def messages(req: MessagesRequest) -> Any:
    """Anthropic-shaped response. Supports both stream=False (single JSON)
    and stream=True (SSE)."""
    user_text = _collect_user_text(req)
    reply_text = _build_reply_text(user_text)
    tokens_seen = _TOKEN_RE.findall(user_text)
    _LAST_RECEIVED["user_text"] = user_text
    _LAST_RECEIVED["tokens_seen"] = tokens_seen
    _LAST_RECEIVED["stream"] = req.stream
    logger.info(
        "mock anthropic request: tokens=%d stream=%s user_text_len=%d",
        len(tokens_seen),
        req.stream,
        len(user_text),
    )

    if not req.stream:
        return JSONResponse(
            {
                "id": "msg_mock_001",
                "type": "message",
                "role": "assistant",
                "model": req.model,
                "content": [{"type": "text", "text": reply_text}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 10},
            }
        )

    # Streaming SSE path: emit a small set of events that mirror what the
    # real Anthropic API sends.
    async def _event_stream():
        import json

        # message_start
        yield (
            'event: message_start\n'
            'data: '
            + json.dumps(
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_mock_001",
                        "type": "message",
                        "role": "assistant",
                        "model": req.model,
                        "content": [],
                        "stop_reason": None,
                    },
                }
            )
            + "\n\n"
        )
        # content_block_start
        yield (
            'event: content_block_start\n'
            'data: '
            + json.dumps(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                }
            )
            + "\n\n"
        )
        # Stream the reply in small pieces so the proxy's streaming
        # restorer has to handle chunk boundaries inside tokens.
        for chunk in _chunked(reply_text, size=4):
            yield (
                'event: content_block_delta\n'
                'data: '
                + json.dumps(
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": chunk},
                    }
                )
                + "\n\n"
            )
        # content_block_stop
        yield (
            'event: content_block_stop\n'
            'data: ' + '{"type":"content_block_stop","index":0}' + "\n\n"
        )
        # message_delta + message_stop
        yield (
            'event: message_delta\n'
            'data: ' + '{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":10}}' + "\n\n"
        )
        yield 'event: message_stop\ndata: {"type":"message_stop"}\n\n'

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"cache-control": "no-cache"},
    )


def _chunked(text: str, size: int):
    for i in range(0, len(text), size):
        yield text[i : i + size]
