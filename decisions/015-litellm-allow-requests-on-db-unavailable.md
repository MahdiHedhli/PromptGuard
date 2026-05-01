# DEC-015: Set `allow_requests_on_db_unavailable: true` on the LiteLLM proxy

**Date:** 2026-05-03
**Status:** Accepted
**Phase:** v1 (v1 carryover closure)
**Author:** Claude Code (autonomous)

---

## Context

`claude` CLI v2.x sends `POST /v1/messages?beta=true`. LiteLLM's auth path
on that route attempts to look up virtual-key state and spend records in
its backing database; without a configured `database_url`, the path
errors with `400 {"error":{"message":"No connected db.",...}}`. The
request never reaches the PromptGuard pre-call hook.

v1 daily report flagged two paths to fix this:
1. Set `general_settings.allow_requests_on_db_unavailable: true`.
2. Strip `?beta=true` at proxy ingress.

Mahdi picked option 1 in the v1 plan.

PromptGuard's threat model treats the proxy as a per-developer local
process. We do not use LiteLLM's spend tracking, virtual-key issuance,
or audit DB; PromptGuard maintains its own audit log inside the
PromptGuardHook. Disabling the DB requirement is the right call for v1
because the DB has no semantic meaning to us; v1.1 may revisit if
PromptGuard moves to a shared / team mode where multi-tenant accounting
matters.

## Options considered

### Option 1: `allow_requests_on_db_unavailable: true` (chosen)
- Pros: One-line config change. Documented LiteLLM setting. Lets the
  CLI request reach our pre-call hook; from there everything works as
  for the curl-based path that was already validated on v1.
- Cons: Disables LiteLLM's spend-tracking / virtual-key features. We
  do not use them.

### Option 2: Middleware that strips `?beta=true`
- Pros: Surgical; touches only the path that fails.
- Cons: We would be writing custom LiteLLM middleware, then maintaining
  it across LiteLLM upgrades. Also: claude CLI may upgrade to send
  other beta flags we have not anticipated; we would need a moving
  target.

### Option 3: Run a thin reverse proxy in front of LiteLLM
- Pros: Total control over request shape.
- Cons: Adds a hop, adds a service to the compose stack. Overkill for a
  config-only fix.

## Decision

Set `general_settings.allow_requests_on_db_unavailable: true` in
`docker/litellm/config.yaml` and `docker/litellm/config-mock.yaml`.

## Consequences

### Enables
- `claude` CLI v2.x sessions through the proxy work end-to-end.
- The pre-call hook fires on the `?beta=true` route, so PromptGuard
  policy applies uniformly across all clients.
- v1 real-key live test can run.

### Constrains
- LiteLLM's spend-tracking + virtual-key features remain disabled. v1
  did not use them; v1.1 may want them back if a shared / team mode is
  introduced.
- A future LiteLLM version may rename or reinterpret this config flag.
  Pinning the LiteLLM image digest at packaging polish (v1) is the
  belt-and-braces fix.

### Revisit if
- PromptGuard moves to a shared / team-server mode in v1.1 and needs
  per-user spend or virtual keys.
- A LiteLLM upgrade changes the meaning of this flag.

## Implementation notes

- Applied to both `config.yaml` (real upstream) and `config-mock.yaml`
  (mock upstream for integration testing).
- No change to the PromptGuard hook. The fix is purely on the LiteLLM
  side.
