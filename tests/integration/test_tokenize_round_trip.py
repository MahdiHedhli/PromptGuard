"""End-to-end TOKENIZE round-trip via mock-Anthropic upstream.

Validates the v1-4 promise: a TOKENIZE-mapped value is replaced with
an unguessable token in the outbound request, the upstream echoes the
token in its response, and the proxy substitutes the original value
back so the user sees their original content.

Run with the mock stack up:
    PROMPTGUARD_LITELLM_CONFIG=./docker/litellm/config-mock.yaml \\
        docker compose --profile mock up -d --wait
    pytest -m mock_upstream tests/integration/test_tokenize_round_trip.py

The mock-anthropic service exposes `/_test/last_received` so we can
assert the upstream saw the token, not the raw PII.
"""

from __future__ import annotations

import json
import os
import re

import httpx
import pytest

LITELLM_URL = os.environ.get("PROMPTGUARD_LITELLM_URL", "http://localhost:4100")
MOCK_URL = os.environ.get("PROMPTGUARD_MOCK_URL", "http://localhost:9099")
MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-promptguard-dev")

TOKEN_RE = re.compile(r"\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]")


async def _stack_up_or_skip() -> None:
    async with httpx.AsyncClient(timeout=3.0) as c:
        try:
            await c.get(f"{LITELLM_URL}/health/liveliness")
            await c.get(f"{MOCK_URL}/health")
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            pytest.skip(
                f"mock stack not up ({type(exc).__name__}); start with "
                f"`docker compose --profile mock up -d --wait`"
            )


def _payload(user_content: str) -> dict:
    return {
        "model": "claude-sonnet-4-6",
        "max_tokens": 120,
        "messages": [{"role": "user", "content": user_content}],
    }


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {MASTER_KEY}",
        "x-api-key": MASTER_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


@pytest.mark.mock_upstream
@pytest.mark.docker
@pytest.mark.integration
async def test_tokenize_round_trip_internal_ip_non_streaming() -> None:
    """Outbound: IP -> token. Mock echoes token. Inbound: token -> IP."""
    await _stack_up_or_skip()
    raw_ip = "10.0.13.42"
    async with httpx.AsyncClient(timeout=15.0) as c:
        resp = await c.post(
            f"{LITELLM_URL}/v1/messages",
            headers=_headers(),
            json=_payload(f"What range is {raw_ip} in?"),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # The user-visible reply must contain the restored original.
        reply_text = body["content"][0]["text"]
        assert raw_ip in reply_text, f"original IP missing from reply: {reply_text!r}"

        # And the upstream must have seen a token, NOT the raw IP.
        seen = await c.get(f"{MOCK_URL}/_test/last_received")
        seen.raise_for_status()
        seen_data = seen.json()
        assert raw_ip not in seen_data["user_text"], (
            f"upstream saw raw IP! user_text={seen_data['user_text']!r}"
        )
        assert len(seen_data["tokens_seen"]) >= 1, (
            f"no tokens reached upstream: {seen_data}"
        )
        assert TOKEN_RE.fullmatch(seen_data["tokens_seen"][0])


@pytest.mark.mock_upstream
@pytest.mark.docker
@pytest.mark.integration
async def test_tokenize_round_trip_streaming() -> None:
    """Same round-trip but with stream=True, exercising SSE rewriter."""
    await _stack_up_or_skip()
    raw_ip = "10.0.13.42"
    body = _payload(f"Echo this back: {raw_ip}")
    body["stream"] = True
    async with httpx.AsyncClient(timeout=15.0) as c:
        # Stream the response and accumulate the user-visible text.
        async with c.stream(
            "POST",
            f"{LITELLM_URL}/v1/messages",
            headers=_headers(),
            json=body,
        ) as resp:
            assert resp.status_code == 200, await resp.aread()
            collected: list[str] = []
            async for raw_event in resp.aiter_text():
                # Each chunk may contain one or more SSE events. We are
                # only after the user-visible text deltas.
                for line in raw_event.split("\n"):
                    if not line.startswith("data: "):
                        continue
                    payload = line[len("data: ") :].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        evt = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    delta = evt.get("delta", {})
                    if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                        collected.append(delta["text"])

        full_text = "".join(collected)
        # Restored content reaches the user.
        assert raw_ip in full_text, f"restored IP missing from streamed reply: {full_text!r}"
        # No raw IP went upstream.
        seen = await c.get(f"{MOCK_URL}/_test/last_received")
        seen_data = seen.json()
        assert raw_ip not in seen_data["user_text"], seen_data
        assert seen_data["stream"] is True


@pytest.mark.mock_upstream
@pytest.mark.docker
@pytest.mark.integration
async def test_tokenize_clean_prompt_round_trip_unchanged() -> None:
    """A clean prompt produces a clean reply; no token traffic either way."""
    await _stack_up_or_skip()
    async with httpx.AsyncClient(timeout=15.0) as c:
        resp = await c.post(
            f"{LITELLM_URL}/v1/messages",
            headers=_headers(),
            json=_payload("Hello there, how are you?"),
        )
        assert resp.status_code == 200
        seen = (await c.get(f"{MOCK_URL}/_test/last_received")).json()
        assert seen["tokens_seen"] == []
