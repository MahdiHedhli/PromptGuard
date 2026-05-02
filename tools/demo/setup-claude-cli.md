# claude CLI through PromptGuard: setup

The canonical demo path for v1.1.1. The claude CLI v2.x respects
`ANTHROPIC_BASE_URL` and `ANTHROPIC_AUTH_TOKEN` environment variables;
pointing them at the local PromptGuard proxy intercepts every request
the CLI sends out.

This setup was validated in v1.1 phase 5 (asset 04) and is the
fallback when Cursor's UI does not expose a clean custom-endpoint
setting (see [`setup-cursor.md`](setup-cursor.md)).

## Prerequisites

- claude CLI v2.x installed (`brew install anthropics/claude/claude` on
  macOS, or follow the Anthropic install docs for your platform).
- PromptGuard stack running:
  ```
  cd /path/to/PromptGuard
  docker compose up -d --wait
  ```
- Real Anthropic API key in `.env` so the upstream actually responds:
  ```
  ANTHROPIC_API_KEY=sk-ant-api03-...
  ```

## Configuration

The CLI takes the override per-invocation. There is no settings file to
edit; you set environment variables on the command line:

```bash
ANTHROPIC_BASE_URL=http://localhost:4100 \
ANTHROPIC_AUTH_TOKEN=sk-promptguard-dev \
ANTHROPIC_API_KEY=sk-promptguard-dev \
claude --print 'your prompt here' --model claude-sonnet-4-6
```

`ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` both set non-empty
placeholders; the real key lives in the LiteLLM container's environment
and is injected on the upstream-bound request.

The default port is 4100 in this repo's compose file. If you have
overridden `PROMPTGUARD_LITELLM_PORT` in `.env`, use that instead.

## Verifying the route

Default policy BLOCKs cloud-API-key shapes. Quick verification:

```bash
ANTHROPIC_BASE_URL=http://localhost:4100 \
ANTHROPIC_AUTH_TOKEN=sk-promptguard-dev \
ANTHROPIC_API_KEY=sk-promptguard-dev \
claude --print 'Triage this leaked key: AKIAFAKE_FAKE_FAKE_FAKE' \
       --model claude-sonnet-4-6
```

PromptGuard returns a structured violation in Anthropic's error
envelope; the CLI prints the error message rather than a completion.
Confirms the request was intercepted and BLOCKed.

## End-to-end TOKENIZE round-trip

The default policy TOKENIZEs internal IPs. Prompt that asks the model
to echo the IP back surfaces the full round-trip:

```bash
ANTHROPIC_BASE_URL=http://localhost:4100 \
ANTHROPIC_AUTH_TOKEN=sk-promptguard-dev \
ANTHROPIC_API_KEY=sk-promptguard-dev \
claude --print 'Repeat back the exact IP address that appears in this
sentence, character for character, with no commentary: 10.0.13.42' \
       --model claude-sonnet-4-6
```

User-visible terminal output (after PromptGuard's reverse path):
```
The IP address in your message has been redacted by the system and
appears as `10.0.13.42`. I don't have access to the original value.
```

Capture from the MITM harness shows:
- request body: `[INTERNAL_IP_<16 hex>]` instead of `10.0.13.42`
- response body: model echoed the same token verbatim
- terminal output: token substituted back to `10.0.13.42`

This is asset 04 from v1.1 phase 5, validated end-to-end.

## Cost notes

Each scenario in the demo set is one round-trip, around 200-1000 input
tokens and 50-300 output tokens. At Anthropic's claude-sonnet-4-6 retail
rate, each round-trip costs around $0.005. The five demo scenarios
together cost under $0.05 at retail; well under the $1 sprint budget
the v1.1.1 brief allocated.
