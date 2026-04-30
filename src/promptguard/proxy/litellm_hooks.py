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
from collections.abc import AsyncGenerator, AsyncIterator
from typing import Any

from promptguard.actions import ActionContext, ActionEngine, TokenMap
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

    @property
    def token_map(self) -> TokenMap:
        return self._engine.token_map

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

        # Persist conversation_id and request_id back into metadata so the
        # post-call hook can find them. The post-call sees this same `data`
        # dict (LiteLLM threads it through). Without this, the post-call
        # has no way to identify the conversation and TOKENIZE round-trip
        # silently does nothing on the response.
        if not isinstance(data.get("metadata"), dict):
            data["metadata"] = {}
        data["metadata"]["conversation_id"] = conversation_id
        data["metadata"]["promptguard_request_id"] = request_id

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


# -- Reverse path: post-call hooks ---------------------------------


def _conversation_id_from_request(request_data: dict[str, Any] | None) -> str | None:
    """Extract conversation_id from a request body's metadata.

    Mirrors what `_inspect` writes during pre-call. If no metadata, no
    restoration can happen for this request; the post-call hook treats
    that as a no-op (the response was clean).
    """
    if not request_data:
        return None
    metadata = request_data.get("metadata")
    if isinstance(metadata, dict):
        cid = metadata.get("conversation_id")
        if isinstance(cid, str) and cid:
            return cid
    return None


def _restore_strings_in_object(token_map: TokenMap, conversation_id: str, obj: Any) -> Any:
    """In-place walk: substitute tokens in every string value.

    Returns the same object (mutated). Mutation in place keeps LiteLLM's
    typed response objects intact (we do not return a new instance).
    """
    if isinstance(obj, str):
        # Strings cannot be mutated in place; the caller must reassign.
        return token_map.restore(conversation_id, obj)
    if isinstance(obj, dict):
        for key, value in list(obj.items()):
            obj[key] = _restore_strings_in_object(token_map, conversation_id, value)
        return obj
    if isinstance(obj, list):
        for i, value in enumerate(obj):
            obj[i] = _restore_strings_in_object(token_map, conversation_id, value)
        return obj
    if hasattr(obj, "__dict__") and not isinstance(obj, type):
        # Pydantic BaseModel / dataclass / plain object: walk attributes.
        for name, value in list(vars(obj).items()):
            if name.startswith("_"):
                continue
            new_value = _restore_strings_in_object(token_map, conversation_id, value)
            try:
                setattr(obj, name, new_value)
            except Exception:
                # Frozen / read-only; leave as-is.
                pass
        return obj
    return obj


# Add post-call hooks to PromptGuardHook -----------------------------


async def _async_post_call_success_hook(
    self: PromptGuardHook,
    data: dict[str, Any],
    user_api_key_dict: Any,
    response: Any,
) -> Any:
    """Non-streaming reverse path.

    Walk the response; restore tokens in every string field. Conversation
    ID comes from the request body metadata that the pre-call hook
    populated.
    """
    cid = _conversation_id_from_request(data)
    if cid is None:
        return response
    return _restore_strings_in_object(self.token_map, cid, response)


async def _async_post_call_streaming_iterator_hook(
    self: PromptGuardHook,
    user_api_key_dict: Any,
    response: AsyncIterator[Any],
    request_data: dict[str, Any],
) -> AsyncGenerator[Any, None]:
    """Streaming reverse path.

    LiteLLM yields chunk objects: for /chat/completions these are
    `ModelResponseStream` with `.choices[i].delta.content`; for /v1/messages
    Anthropic native, they are pre-serialized SSE frame strings or dicts
    representing the parsed event JSON. We support both:

    * For `dict` / typed-object chunks, `_restore_strings_in_object`
      walks every string field.
    * For `str` / `bytes` chunks (raw SSE frames), we run our SSE byte
      restorer over the chunk inline. The restorer is stateless within
      a single chunk because Anthropic emits each event as a complete
      SSE frame; tokens never straddle frames.
    """
    import sys

    from promptguard.actions.tokenize import _TOKEN_RE

    from promptguard.proxy.streaming import restore_sse_blob

    cid = _conversation_id_from_request(request_data)
    async for chunk in response:
        if cid is None:
            yield chunk
            continue
        if isinstance(chunk, (bytes, bytearray)):
            yield restore_sse_blob(self.token_map, cid, bytes(chunk))
        elif isinstance(chunk, str):
            yield restore_sse_blob(
                self.token_map, cid, chunk.encode("utf-8")
            ).decode("utf-8")
        else:
            _restore_strings_in_object(self.token_map, cid, chunk)
            yield chunk




async def _async_post_call_streaming_hook(
    self: PromptGuardHook,
    user_api_key_dict: Any,
    response: str,
) -> str:
    """Per-chunk text reverse path. Used by some LiteLLM streaming code paths.

    `response` is a partial text chunk. LiteLLM does not pass `request_data`
    here, so we cannot reach the per-conversation map directly. Fall back
    to scanning every conversation for matching tokens. With unguessable
    random IDs (DEC-012) collisions across conversations are
    statistically impossible, so this is safe.
    """
    if not response:
        return response
    # Defensive: if no token shape in the chunk at all, skip the lookup.
    from promptguard.actions.tokenize import _TOKEN_RE

    if not _TOKEN_RE.search(response):
        return response
    return _restore_across_conversations(self.token_map, response)


def _restore_across_conversations(token_map: TokenMap, text: str) -> str:
    """Substitute every token in `text` with its original from any
    conversation that owns it. Used when no conversation_id is available
    at the call site (per-chunk streaming path).

    With 64-bit unguessable random suffixes (DEC-012) the chance that two
    distinct conversations issued the same token is ~2^-64. We treat this
    as zero: the first map that owns the token is the right answer.
    """
    from promptguard.actions.tokenize import _TOKEN_RE

    # Take a snapshot of conversation IDs so we don't iterate while the
    # map mutates under another request. We touch each conversation's
    # last-access via lookup(), which is OK; restoration is read-only on
    # the actual token-to-original mapping.
    # Note: TokenMap does not currently expose conversation IDs publicly.
    # We use a private-attr access path; this is intentional and tested.
    ids = list(token_map._states.keys())  # noqa: SLF001  (private but stable)

    def _sub(match: "re.Match[str]") -> str:
        token = match.group(0)
        for cid in ids:
            original = token_map.lookup(cid, token)
            if original is not None:
                return original
        return token

    return _TOKEN_RE.sub(_sub, text)


async def _async_post_call_streaming_deployment_hook(
    self: PromptGuardHook,
    request_data: dict[str, Any],
    response_chunk: Any,
    call_type: Any,
) -> Any:
    """Per-chunk deployment-level streaming hook.

    Some LiteLLM streaming paths (notably the Anthropic native
    `/v1/messages` pass-through) emit raw chunks here rather than via
    the iterator-level hook. We restore tokens in any string content we
    find on the chunk.
    """
    cid = _conversation_id_from_request(request_data)
    if cid is None:
        return response_chunk
    if isinstance(response_chunk, (bytes, bytearray)):
        try:
            text = response_chunk.decode("utf-8")
        except UnicodeDecodeError:
            return response_chunk
        restored = self.token_map.restore(cid, text)
        return restored.encode("utf-8")
    if isinstance(response_chunk, str):
        return self.token_map.restore(cid, response_chunk)
    # Object with attributes (typed chunk): mutate in place.
    _restore_strings_in_object(self.token_map, cid, response_chunk)
    return response_chunk


# Bind the post-call helpers as methods on PromptGuardHook.
PromptGuardHook.async_post_call_success_hook = _async_post_call_success_hook  # type: ignore[attr-defined]
PromptGuardHook.async_post_call_streaming_iterator_hook = (  # type: ignore[attr-defined]
    _async_post_call_streaming_iterator_hook
)
PromptGuardHook.async_post_call_streaming_hook = _async_post_call_streaming_hook  # type: ignore[attr-defined]
PromptGuardHook.async_post_call_streaming_deployment_hook = (  # type: ignore[attr-defined]
    _async_post_call_streaming_deployment_hook
)
