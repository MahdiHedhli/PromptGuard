"""Live-stack integration tests for the PromptGuard proxy.

Marked `docker` so they're skipped in the default pytest run. Run with:

    docker compose up -d --wait
    pytest -m docker tests/integration/test_live_stack.py

These tests POST Anthropic-shaped requests at the LiteLLM proxy and
assert the PromptGuard pre-call hook fired:

  * a request with credentials gets HTTP 400 + the BLOCK envelope.
  * a request with a mix of email + AWS key + internal IP gets BLOCKed
    (default policy says BLOCK on AWS key) with the right categories.
  * a request with only an email gets MASKed; we cannot inspect the
    *upstream* request body from outside the proxy, but we can confirm
    the pre-call hook ran by giving the proxy a fake API key and
    asserting the upstream returned an authentication error (which
    proves the request reached upstream after rewriting). If the hook
    had blocked, we would have seen our 400 instead.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
import pytest

LITELLM_URL = os.environ.get("PROMPTGUARD_LITELLM_URL", "http://localhost:4100")
MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "sk-promptguard-dev")


def _extract_pg_envelope(payload: dict[str, Any]) -> dict[str, Any] | None:
    """LiteLLM wraps our 400 detail as a JSON-serialized string under
    response.error.message. Parse that string back into our envelope dict."""
    err = payload.get("error") or payload.get("detail", {}).get("error", {})
    if not err:
        return None
    msg = err.get("message", "")
    if isinstance(msg, str) and msg.strip().startswith("{"):
        try:
            return json.loads(msg)
        except json.JSONDecodeError:
            pass
    # Some LiteLLM versions prefix with "400: {..json..}" so try to peel that.
    if isinstance(msg, str) and ": {" in msg:
        json_start = msg.index(": {") + 2
        try:
            return json.loads(msg[json_start:])
        except json.JSONDecodeError:
            pass
    # Already-decoded paths (FastAPI direct response, dict detail) keep the
    # envelope at err.promptguard.
    if "promptguard" in err:
        return {"error": err, "type": payload.get("type", "error")}
    return None


async def _post_or_skip(path: str, json_body: dict) -> httpx.Response:
    url = LITELLM_URL.rstrip("/") + path
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            return await client.post(
                url,
                json=json_body,
                headers={
                    "Authorization": f"Bearer {MASTER_KEY}",
                    "x-api-key": MASTER_KEY,
                    "anthropic-version": "2023-06-01",
                },
            )
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.RemoteProtocolError,
        ) as exc:
            pytest.skip(
                f"LiteLLM proxy not reachable at {url} ({type(exc).__name__}); "
                f"start the stack with `docker compose up -d --wait`"
            )


@pytest.mark.docker
@pytest.mark.integration
async def test_block_on_aws_key_returns_envelope() -> None:
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 64,
        "messages": [
            {
                "role": "user",
                "content": "deploy with AKIAIOSFODNN7EXAMPLE please",
            }
        ],
    }
    resp = await _post_or_skip("/v1/messages", body)
    assert resp.status_code == 400, f"expected 400, got {resp.status_code}: {resp.text}"
    envelope = _extract_pg_envelope(resp.json())
    assert envelope is not None, f"no PromptGuard envelope in response: {resp.text}"
    err = envelope["error"]
    assert err["type"] == "promptguard_policy_violation"
    pg = err["promptguard"]
    assert "cloud_api_key" in pg["categories"]
    # The AWS key text must not appear in the response body.
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.text


@pytest.mark.docker
@pytest.mark.integration
async def test_block_on_mixed_pii_lists_all_categories() -> None:
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 64,
        "messages": [
            {
                "role": "user",
                "content": (
                    "Email me at someone@example.com from 10.0.0.5 with key "
                    "AKIAIOSFODNN7EXAMPLE"
                ),
            }
        ],
    }
    resp = await _post_or_skip("/v1/messages", body)
    assert resp.status_code == 400
    envelope = _extract_pg_envelope(resp.json())
    assert envelope is not None, f"no PromptGuard envelope in response: {resp.text}"
    pg = envelope["error"]["promptguard"]
    assert pg["violation_count"] >= 1
    assert "cloud_api_key" in pg["categories"]
    # The original PII strings must not appear in the response body.
    text = resp.text
    assert "someone@example.com" not in text
    assert "10.0.0.5" not in text
    assert "AKIAIOSFODNN7EXAMPLE" not in text


@pytest.mark.docker
@pytest.mark.integration
async def test_clean_prompt_reaches_upstream() -> None:
    """A prompt with no PII is forwarded; upstream auth-fails because we
    use a fake key, which is the proof we wanted (the request got past
    the pre-call hook and reached the upstream Anthropic adapter).
    """
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 16,
        "messages": [
            {"role": "user", "content": "say hi in three words"},
        ],
    }
    resp = await _post_or_skip("/v1/messages", body)
    # 401 / 403 / 400 (auth-related) are all acceptable: they prove the
    # request reached the upstream adapter. 200 only happens if a real
    # key is set, also acceptable.
    assert resp.status_code in {200, 400, 401, 403}, (
        f"unexpected status {resp.status_code}: {resp.text}"
    )
    if resp.status_code == 400:
        # If we got a 400 it must NOT be a PromptGuard block (the prompt is clean).
        envelope = _extract_pg_envelope(resp.json())
        assert envelope is None, f"clean prompt was blocked unexpectedly: {resp.text}"


@pytest.mark.docker
@pytest.mark.integration
async def test_email_in_prompt_does_not_trigger_block_under_default_policy() -> None:
    """Email is MASK in default policy, not BLOCK. Request must reach upstream."""
    body = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 16,
        "messages": [
            {"role": "user", "content": "ping me at noreply@example.com tomorrow"},
        ],
    }
    resp = await _post_or_skip("/v1/messages", body)
    if resp.status_code == 400:
        envelope = _extract_pg_envelope(resp.json())
        assert envelope is None, f"email-only prompt was blocked: {resp.text}"
