"""BLOCK error envelope.

Matches the shape produced by both Anthropic and OpenAI on a 4xx error so
that any client that already understands those providers parses our
violation cleanly without custom handling.

Anthropic shape:
    { "type": "error",
      "error": { "type": "invalid_request_error", "message": "..." } }

OpenAI shape:
    { "error": { "message": "...", "type": "...", "code": "...", "param": null } }

We emit a hybrid envelope that carries both shapes' required keys, plus a
PromptGuard-specific extension at `error.promptguard` so operators can
machine-correlate by request_id without parsing the message string.

Critical: the envelope MUST NOT include the offending text. The user
already knows what they typed; the error tells them which category
violated. Echoing the text would defeat the threat model.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from promptguard.actions.base import Violation

ERROR_TYPE = "promptguard_policy_violation"
ERROR_CODE = "policy_violation"


def build_block_envelope(
    violations: Iterable[Violation],
    *,
    request_id: str,
    policy_name: str,
    policy_version: str,
) -> dict[str, Any]:
    vlist = list(violations)
    categories = sorted({v.category for v in vlist})
    detectors = sorted({v.detector for v in vlist})
    summary = (
        f"Request blocked by PromptGuard policy '{policy_name}' v{policy_version}. "
        f"{len(vlist)} violation(s) across {len(categories)} categor"
        f"{'y' if len(categories) == 1 else 'ies'}: "
        f"{', '.join(categories)}. "
        f"See request_id={request_id} for audit correlation. "
        f"Original prompt is not echoed by design (see docs/threat-model.md A6)."
    )
    promptguard_block = {
        "request_id": request_id,
        "policy_name": policy_name,
        "policy_version": policy_version,
        "violation_count": len(vlist),
        "categories": categories,
        "detectors": detectors,
        # Per-violation rows. Confidence rounded to 2dp for stable wire output.
        "violations": [
            {
                "category": v.category,
                "detector": v.detector,
                "confidence": round(v.confidence, 2),
            }
            for v in vlist
        ],
    }
    error_obj = {
        # OpenAI keys
        "message": summary,
        "type": ERROR_TYPE,
        "code": ERROR_CODE,
        "param": None,
        # PromptGuard extension; consumers can ignore
        "promptguard": promptguard_block,
    }
    return {
        # Anthropic top-level "type"
        "type": "error",
        "error": error_obj,
    }


def render_envelope(envelope: dict[str, Any]) -> str:
    """JSON serialize the envelope. Stable key order for testability."""
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))


def assert_no_payload_leak(envelope: dict[str, Any], original_text: str) -> None:
    """Defensive helper: refuse to send an envelope that contains any
    substring of the original text longer than 6 characters. Used in tests
    and as a runtime guard inside the LiteLLM hook.
    """
    serialized = json.dumps(envelope)
    # Six-char windows of the original; if any appears verbatim in the
    # serialized envelope, we leaked. Skip windows containing only common
    # whitespace or punctuation to avoid trivial collisions ("the user").
    seen_windows: set[str] = set()
    for i in range(len(original_text) - 6):
        window = original_text[i : i + 6]
        if window.isspace() or all(not ch.isalnum() for ch in window):
            continue
        seen_windows.add(window)
    leaked = [w for w in seen_windows if w in serialized]
    if leaked:
        raise AssertionError(
            f"BLOCK envelope leaked content from the original prompt: {leaked[:3]}..."
        )
