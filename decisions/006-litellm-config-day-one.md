# DEC-006: Day-1 LiteLLM config is vanilla, hooks land Day 2

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** Day 1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

The Day-1 validation gate requires `docker compose up` to succeed and a simple integration test to confirm a prompt routes through the stack. It does *not* require the action engine to rewrite payloads (DEC-004) or for the proxy to enforce policy.

LiteLLM supports custom callbacks for pre-call and post-call hooks. The natural place for PromptGuard to plug in is via these hooks. But the action engine rewrite is not implemented until Day 2 — so wiring the hooks today against a no-op rewrite is premature.

## Decision

Day 1 ships a vanilla LiteLLM config (`docker/litellm/config.yaml`) with Anthropic and OpenAI-compatible upstreams. No PromptGuard custom callbacks. The proxy forwards traffic without inspection.

The `DetectionPipeline` and `ActionEngine` are exercised end-to-end by the Day-1 integration test, which constructs them in-process and runs them against synthetic PII. This satisfies "PII detection available, even if action engine is stubbed."

Day 2 adds a `litellm.CustomLogger`-based pre-call callback that runs the pipeline + engine and either rejects (BLOCK) or rewrites (MASK).

## Consequences

### Enables
- `docker compose up -d` starts cleanly today.
- The Day-2 author lands a single behavioral change rather than a config + rewrite + handoff in the same commit.

### Constrains
- Anyone running the Day-1 stack with API keys gets unmediated forwarding. The Day-1 README is explicit about this.

### Revisit if
- We discover LiteLLM's callback contract has changed since the v1 design (it has been stable; low risk).

## Implementation notes

- `docker/litellm/config.yaml` references `os.environ/ANTHROPIC_API_KEY` etc. Keys are not in the file or in the image.
- `LITELLM_MASTER_KEY` defaults to `sk-promptguard-dev` so the proxy starts without requiring the user to set anything; the README warns against using the default in any non-local context.
- Day 2's callback will live in `src/promptguard/proxy/litellm_hooks.py`.
