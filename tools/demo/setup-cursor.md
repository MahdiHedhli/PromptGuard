# Cursor through PromptGuard: setup

Cursor's "Custom OpenAI-compatible API" setting routes all model traffic
through a host you specify. Pointing it at the local PromptGuard proxy
gives the same interception PromptGuard provides for any other API
client.

## Prerequisites

- Cursor (any version that exposes "OpenAI API Key" + "OpenAI Base URL"
  in Settings -> Models. As of 2026-05, this is the standard path; the
  setting names occasionally rename across releases. Check the in-app
  search bar for "base URL" if the menu item moved.)
- PromptGuard stack running locally:
  ```
  cd /path/to/PromptGuard
  docker compose up -d --wait
  ```
  Verify: `curl http://localhost:4000/health/liveliness` returns
  `"I'm alive!"`.

## Configuration

### Cursor side

1. Open Cursor -> Settings (Cmd+, on macOS).
2. Navigate to Models (or whichever section in the current Cursor
   version exposes the OpenAI-compatible endpoint settings).
3. Set:
   - **OpenAI API Key**: any non-empty placeholder, e.g.
     `sk-promptguard-dev`. Cursor validates the field is non-empty;
     PromptGuard does not require a real upstream key here because the
     real key is injected by LiteLLM container env (via `.env`).
   - **OpenAI Base URL**: `http://localhost:4000/v1`
   - Enable any "Use Custom OpenAI" or equivalent toggle.
4. Save and restart Cursor (it does not always pick up endpoint
   changes without a restart).

### Anthropic models via Cursor

Cursor routes Anthropic model traffic through its own proxy by default;
the OpenAI-compatible endpoint setting above only affects OpenAI traffic.
For Anthropic-model interception, two paths:

- Use Cursor's native OpenAI endpoint (set the chat model to a
  GPT-class model in Cursor) and let Cursor route through PromptGuard
  for that traffic.
- For claude-shaped traffic, use the claude CLI path documented in
  [`setup-claude-cli.md`](setup-claude-cli.md). Cursor's Anthropic
  path is not configurable to a custom URL on the current versions.

## Verifying the route

Before any captures, confirm Cursor actually routes through PromptGuard:

1. Run `make -C tools/mitm-verify up` to start the MITM harness.
   The harness positions mitmproxy between LiteLLM and the upstream so
   we capture what leaves the machine, not what enters it.
2. In Cursor, type a one-line prompt with a synthetic credential-shaped
   string, e.g. `What does AKIAFAKE_FAKE_FAKE_FAKE look like?` and
   send it.
3. PromptGuard's default policy BLOCKs cloud-API-key shapes. You should
   see Cursor surface an error or violation message rather than a
   normal completion.
4. Inspect the latest capture in `local/mitm-captures/`:
   ```
   ls -t local/mitm-captures/ | head -3
   ```
   For a BLOCK, the request body should not exist (the proxy
   short-circuits before forwarding) and the suspicious-pattern count
   should remain zero.

If Cursor sent a request that bypassed PromptGuard, the mitmproxy
capture would show the original credential string in the upstream-bound
body. That is the negative signal.

## Version notes

Cursor's settings UI changes between versions. As of 2026-05:

- The base-URL field is at Settings -> Models -> "Override OpenAI Base URL".
- If you do not see that field, search the settings panel for "base url" or
  enable "OpenAI" as a model provider explicitly.

If your Cursor version ships an entirely different model-provider model,
fall back to claude CLI per [`setup-claude-cli.md`](setup-claude-cli.md).
The claude-CLI route is the canonical demo path for v1.1.1 because it is
fully scriptable and does not depend on a desktop-app UI.

## Caveats

- Cursor's autocomplete, "Cmd+K" inline edits, and "Cmd+L" chat may
  use different routing internally; not every code path respects the
  base-URL override. Verify the specific feature you care about routes
  through PromptGuard before trusting the demo.
- Cursor sends the system reminder, project context, and selected code
  with each request. The capture will show that PromptGuard inspected
  all of it (which is the intended behavior).
