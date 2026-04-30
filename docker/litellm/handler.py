"""LiteLLM callbacks entry point for PromptGuard.

LiteLLM resolves `litellm_settings.callbacks: handler.proxy_handler_instance`
to this module. The instance must subclass `CustomLogger` for LiteLLM to
register it in the request lifecycle, so we wrap the provider-agnostic
PromptGuardHook in a thin CustomLogger subclass here.

This module imports `litellm` at runtime; it is only imported inside the
LiteLLM container, where litellm is available. Unit tests do not import
this module so they run without a litellm dep.

Importing this module fails loudly if the policy file or any required
detector service is misconfigured. That is the desired behavior per the
Day-2 brief: "fail loud, never silently fall back."
"""

from __future__ import annotations

import logging
from typing import Any

from litellm.integrations.custom_logger import CustomLogger

from promptguard.proxy.litellm_hooks import PromptGuardHook

logger = logging.getLogger("promptguard.handler")


class PromptGuardCallback(CustomLogger):
    """Thin LiteLLM CustomLogger that delegates to PromptGuardHook."""

    def __init__(self) -> None:
        super().__init__()
        self._hook = PromptGuardHook.from_env()
        logger.info("PromptGuard callback registered with LiteLLM")

    async def async_pre_call_hook(
        self,
        user_api_key_dict: Any,
        cache: Any,
        data: dict[str, Any],
        call_type: str,
    ) -> dict[str, Any]:
        return await self._hook.async_pre_call_hook(
            user_api_key_dict, cache, data, call_type
        )

    async def async_post_call_success_hook(
        self,
        data: dict[str, Any],
        user_api_key_dict: Any,
        response: Any,
    ) -> Any:
        return await self._hook.async_post_call_success_hook(
            data, user_api_key_dict, response
        )

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: Any,
        response: Any,
        request_data: dict[str, Any],
    ) -> Any:
        async for chunk in self._hook.async_post_call_streaming_iterator_hook(
            user_api_key_dict, response, request_data
        ):
            yield chunk

    async def async_post_call_streaming_hook(
        self,
        user_api_key_dict: Any,
        response: str,
    ) -> str:
        return await self._hook.async_post_call_streaming_hook(
            user_api_key_dict, response
        )

    async def async_post_call_streaming_deployment_hook(
        self,
        request_data: dict[str, Any],
        response_chunk: Any,
        call_type: Any,
    ) -> Any:
        return await self._hook.async_post_call_streaming_deployment_hook(
            request_data, response_chunk, call_type
        )


proxy_handler_instance = PromptGuardCallback()
