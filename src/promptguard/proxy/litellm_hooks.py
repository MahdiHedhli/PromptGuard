"""LiteLLM pre-call hook.

Plugs into LiteLLM's `CustomLogger.async_pre_call_hook` extension point.
On each pre-call:

  1. Extract inspectable strings from the request body (system prompt,
     message contents, tool_result blocks).
  2. Run the DetectionPipeline over the concatenated text.
  3. Run the ActionEngine.
  4. If blocked, raise a `litellm.exceptions.BadRequestError` whose body is
     our PromptGuard error envelope (Anthropic + OpenAI compatible).
  5. Otherwise, write rewritten strings back at their original paths.

This file is imported by the LiteLLM container at startup. The handler
module at `docker/litellm/handler.py` exposes
`proxy_handler_instance = PromptGuardHook(...)` for LiteLLM's
`callbacks: <module>.proxy_handler_instance` config.

LiteLLM's hook signature has been moving (the `Guardrail` interface
arrived after CustomLogger). We target CustomLogger because it is stable
across the v1.45+ line; if/when guardrails stabilize further we add a
parallel adapter rather than retrofit this one.
"""

from __future__ import annotations

import logging
import os
import secrets
import time
from typing import Any

from promptguard.actions import ActionContext, ActionEngine
from promptguard.actions.base import Violation
from promptguard.core.detection import DetectionPipeline
from promptguard.core.pipeline_factory import build_pipeline_from_policy
from promptguard.core.policy import Policy
from promptguard.policies.local_yaml import LocalYAMLPolicy
from promptguard.proxy.errors import build_block_envelope
from promptguard.proxy.messages import (
    extract_inspectable_strings,
    join_for_inspection,
    set_at_path,
    split_after_inspection,
)

logger = logging.getLogger("promptguard.proxy")


class BlockedByPolicy(Exception):
    """Raised inside the hook when policy says reject. Carries the envelope."""

    def __init__(self, envelope: dict[str, Any]) -> None:
        self.envelope = envelope
        super().__init__(envelope["error"]["message"])


class PromptGuardHook:
    """LiteLLM CustomLogger that runs PromptGuard on every pre-call."""

    def __init__(
        self,
        policy: Policy,
        pipeline: DetectionPipeline,
        engine: ActionEngine,
    ) -> None:
        self._policy = policy
        self._pipeline = pipeline
        self._engine = engine

    @classmethod
    def from_env(cls) -> PromptGuardHook:
        """Build a hook from environment variables. Used by the container.

        PROMPTGUARD_POLICY_FILE: path to YAML policy (default policies/default.yaml)
        PROMPTGUARD_OPF_URL:     OPF service URL
        PROMPTGUARD_PRESIDIO_URL: Presidio analyzer URL
        """
        policy_file = os.environ.get(
            "PROMPTGUARD_POLICY_FILE", "/app/policies/default.yaml"
        )
        policy = LocalYAMLPolicy(policy_file).load()
        pipeline = build_pipeline_from_policy(policy)
        engine = ActionEngine(policy)
        logger.info(
            "PromptGuard hook initialized: policy=%s v=%s detectors=%s",
            policy.name,
            policy.version,
            [d.name for d in pipeline.detectors],
        )
        return cls(policy, pipeline, engine)

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict[str, Any],
        call_type: str,
    ) -> dict[str, Any]:
        """LiteLLM pre-call extension point.

        Returns the (possibly rewritten) request body. On block, raises
        a FastAPI HTTPException so LiteLLM returns 400 to the client with
        our PromptGuard envelope as the response body.
        """
        try:
            return await self._inspect(data)
        except BlockedByPolicy as exc:
            # LiteLLM wraps HTTPException detail through `str(detail)` rather
            # than json-serializing the dict, so passing detail=<dict> ends up
            # as a Python repr in the wire response. Serialize the envelope to
            # JSON ourselves and surface it as the detail string. Clients then
            # parse `response.json()["error"]["message"]` as JSON to recover
            # the envelope. Imports are lazy so unit tests can run without
            # fastapi (which is in the proxy / opf-service extras).
            import json as _json

            from fastapi import HTTPException

            raise HTTPException(
                status_code=400,
                detail=_json.dumps(exc.envelope, separators=(",", ":")),
            ) from exc

    async def _inspect(self, data: dict[str, Any]) -> dict[str, Any]:
        request_id = _new_request_id()
        conversation_id = (
            data.get("metadata", {}).get("conversation_id")
            if isinstance(data.get("metadata"), dict)
            else None
        ) or request_id

        paths_and_strings = extract_inspectable_strings(data)
        if not paths_and_strings:
            return data

        joined = join_for_inspection([s for _p, s in paths_and_strings])

        t0 = time.perf_counter()
        detections = await self._pipeline.detect_all(joined)
        t_detect_ms = (time.perf_counter() - t0) * 1000.0

        t0 = time.perf_counter()
        result = self._engine.apply(
            joined,
            detections,
            ActionContext(conversation_id=conversation_id, request_id=request_id),
        )
        t_action_ms = (time.perf_counter() - t0) * 1000.0

        logger.info(
            "promptguard pre-call: request_id=%s policy=%s detect_ms=%.2f "
            "action_ms=%.2f detections=%d blocked=%s",
            request_id,
            self._policy.name,
            t_detect_ms,
            t_action_ms,
            len(detections),
            result.blocked,
        )

        if result.blocked:
            envelope = build_block_envelope(
                result.violations,
                request_id=request_id,
                policy_name=self._policy.name,
                policy_version=self._policy.version,
            )
            raise BlockedByPolicy(envelope)

        # Rewrite paths back into the body.
        rewritten_parts = split_after_inspection(
            result.rewritten_text, len(paths_and_strings)
        )
        for (path, _original), new_value in zip(
            paths_and_strings, rewritten_parts, strict=True
        ):
            set_at_path(data, path, new_value)

        return data


def _new_request_id() -> str:
    return f"pg_{int(time.time())}_{secrets.token_hex(4)}"


def _coerce_violations(raw: Any) -> list[Violation]:
    """Used by tests to construct fake violations from dicts."""
    out: list[Violation] = []
    for v in raw or []:
        out.append(Violation(category=v["category"], detector=v["detector"], confidence=v.get("confidence", 1.0)))
    return out
