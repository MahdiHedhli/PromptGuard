# DEC-010: LiteLLM bridge: handler subclasses CustomLogger; PromptGuardHook stays clean

**Date:** 2026-05-01
**Status:** Accepted
**Phase:** v1 (action engine + LiteLLM hook)
**Author:** MahdiHedhli

---

## Context

LiteLLM's pre-call extension point is `CustomLogger.async_pre_call_hook`.
The proxy resolves `litellm_settings.callbacks: handler.proxy_handler_instance`
to a Python instance and registers it for the request lifecycle. For
LiteLLM to actually fire the hook, the registered instance must be a
subclass of `litellm.integrations.custom_logger.CustomLogger`.

This creates a dependency question. PromptGuardHook contains the actual
detection / action / envelope logic. Should it import `litellm` directly?

## Options considered

### Option 1: PromptGuardHook subclasses CustomLogger
- Pros: One class, one file.
- Cons: Forces every consumer of `PromptGuardHook` to have litellm
  installed. Unit tests would need litellm. Other proxy adapters (a
  future Cursor-native or Continue.dev plugin) would still drag a
  litellm dependency.

### Option 2: PromptGuardHook is provider-agnostic; container-side
handler module bridges to LiteLLM (chosen)
- Pros: PromptGuardHook stays free of litellm imports. Unit tests
  import it without litellm. The bridge lives in `docker/litellm/handler.py`,
  which only runs inside the LiteLLM container where litellm is
  available. Future adapters for other proxy stacks are isolated bridges,
  not retrofits to the core.
- Cons: One extra ~30-line bridge file per proxy stack. Acceptable.

### Option 3: Use LiteLLM's `Guardrail` interface instead of CustomLogger
- Pros: Newer, purpose-built for content policy.
- Cons: API has been moving. We need a stable target for v1; revisit in
  v1.1 once Guardrail stabilizes.

## Decision

Chose Option 2. `PromptGuardHook` lives in
`src/promptguard/proxy/litellm_hooks.py` with no `litellm` import.
`docker/litellm/handler.py` defines a small `PromptGuardCallback` class
that subclasses `CustomLogger` and delegates `async_pre_call_hook` to a
`PromptGuardHook` instance. The handler module is copied into the
LiteLLM container at build time and referenced in
`config.yaml` as `litellm_settings.callbacks: handler.proxy_handler_instance`.

Block path: when `_inspect()` raises `BlockedByPolicy`, the hook converts
the envelope into a JSON-serialized FastAPI `HTTPException` with status
400. LiteLLM wraps the detail in its own error envelope by `str()`-ing
the detail; passing detail as a JSON string (not a dict) preserves the
envelope shape on the wire. Clients parse
`response["error"]["message"]` as JSON to recover the PromptGuard envelope.

## Consequences

### Enables
- Unit tests run without litellm in the test environment.
- Future Cursor-native, Continue.dev, or VS Code-extension adapters reuse
  PromptGuardHook unchanged.
- LiteLLM's exception wrapping does not corrupt our envelope.

### Constrains
- We carry one bridge file per proxy stack. Two bridges total at v1
  (LiteLLM today, browser extension in v1.1).
- Clients that consume our 400 response must parse `error.message` as
  JSON. We document this in the policy-schema doc and live-stack tests.
  If LiteLLM changes its exception-wrapping behavior, we revisit.

### Revisit if
- LiteLLM stabilizes the `Guardrail` interface enough that we could swap
  CustomLogger for it without losing the FastAPI HTTPException path.
- Another proxy stack lands and the bridge pattern shows wear.

## Implementation notes

- Container image: `docker/litellm/Dockerfile` extends
  `ghcr.io/berriai/litellm:main-stable`, bootstraps pip + uv, and
  `uv pip install /tmp/pg`. The upstream image ships a uv-managed venv
  pinned to `uv==0.10.9`; we install that exact version to avoid
  re-resolving the lock.
- Handler instance is created once at module import. Module-level
  exceptions during construction (policy-file missing, OPF unavailable)
  cause LiteLLM startup to fail loudly, which is the desired hard-fail
  behavior.
- The hook records detection latency and action-engine latency per
  request and logs at INFO with the request_id, so operators can grep
  `request_id=pg_...` to correlate with the audit log.
