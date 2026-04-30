# PromptGuard Architecture

A reader-friendly walkthrough of how PromptGuard is put together. For decision rationale and locked trade-offs, see `docs/research-notes.md`.

## The picture

```
                   +-------------------------------+
   AI tool ---->   |  LiteLLM (local, port 4000)   |
   (Claude Code,   |                               |
   Cursor, ...)    |   pre-call hook ----+         |
                   |                     |         |
                   |   post-call hook    |         |
                   +--------|------------+---------+
                            |            |
                            v            v
                   +------------------+  +-----------------+
                   | DetectionPipeline|  | TokenRestorer   |
                   |                  |  | (per-convo map) |
                   |  Regex          |  +-----------------+
                   |  OPF (HTTP)     |          ^
                   |  Presidio (HTTP)|          |
                   |  LLM judge (off)|          |
                   +------------------+          |
                            |                    |
                            v                    |
                   +------------------+           |
                   |   ActionEngine   |           |
                   |   BLOCK / MASK / |-----------+
                   |   TOKENIZE       |
                   +------------------+
                            ^
                            |
                   +------------------+
                   |  PolicyAdapter   |
                   |  (LocalYAML)     |
                   +------------------+
```

## Components

### LiteLLM proxy (edge)

LiteLLM is the entry point. It exposes Anthropic and OpenAI-compatible endpoints on `localhost:4000`. PromptGuard plugs in as pre-call and post-call hooks (custom callbacks), giving us control over both the outbound payload and the streamed response.

### DetectionPipeline (core)

A small orchestrator that fans a payload out to every configured detector and aggregates their outputs into a list of `Detection` objects. Detectors run in parallel where they're independent. Any detector flagging a span is sufficient to trigger the policy-mapped action.

### Detectors

| Detector             | What it catches                                              | Where it runs                  |
|----------------------|--------------------------------------------------------------|---------------------------------|
| RegexDetector        | Structured secrets: PEM keys, AWS / GCP / Azure credentials, DB URLs, JWTs, RFC 1918, domains, emails | In-process |
| OPFDetector          | Context-aware PII: names, addresses, phones, free-form secrets | HTTP to `opf-service` container |
| PresidioDetector     | Org-specific custom recognizers                              | HTTP to Presidio analyzer       |
| LLMJudgeDetector     | Paraphrased / adversarial reformulations (off by default)    | HTTP to local Ollama            |

### ActionEngine

Maps each `(span, category, confidence)` to a policy decision: BLOCK, MASK, or TOKENIZE. Rewrites the payload accordingly. For TOKENIZE, allocates a per-conversation token from a CSPRNG-backed namespace and records the mapping.

### TokenRestorer

Streams the LLM response, scans for tokens issued during pre-call, and substitutes the originals back. Uses a buffering window (default 256 chars, tunable) to handle tokens that straddle SSE chunks.

### Policy sources

| Adapter             | Status (v1)               | What it does                                  |
|---------------------|---------------------------|-----------------------------------------------|
| LocalYAMLPolicy     | Reference, default        | Reads `policies/<name>.yaml`                   |
| GitManifestPolicy   | Adapter framework only    | Pulls signed manifests from a Git repo         |
| PurviewDLPPolicy    | PoC stub + sample import  | Translates Microsoft Purview SITs to PG rules  |
| ICAPPolicy          | PoC stub + sample fixtures| Routes scan requests through an ICAP server    |

## Data flow, end to end

1. AI tool sends a request to `http://localhost:4000`.
2. LiteLLM invokes the pre-call hook with the payload.
3. `DetectionPipeline` runs every configured detector against the prompt.
4. `ActionEngine` reads the active `Policy` and decides per-span: BLOCK, MASK, or TOKENIZE.
5. If anything is BLOCKed, the request is rejected with a structured error and the audit log is written.
6. Otherwise, the rewritten payload is forwarded upstream.
7. LiteLLM streams the response back; the post-call hook pipes it through `TokenRestorer`, which substitutes original values back into the response in real time.
8. The audit log records: detections, actions, policy version, conversation ID. Original values are never persisted.

## Containers

`docker-compose.yml` brings up three services:

- `litellm`: the proxy, port 4000.
- `presidio-analyzer`: Microsoft Presidio analyzer, internal-only.
- `opf-service`: a thin FastAPI server wrapping the OpenAI Privacy Filter Hugging Face model, internal-only.

The Presidio anonymizer is deliberately not used: PromptGuard does its own action engine because Presidio's anonymization vocabulary does not cleanly express our `BLOCK`/`MASK`/`TOKENIZE` semantics (in particular, reversible TOKENIZE with per-conversation scope and unguessable token IDs is not Presidio's model).

## What is deliberately out of scope at v1

- Centralized proxy mode (deferred to v1.1; mobile users are addressed there)
- Browser extension (v1.1/v2)
- Image and file scanning
- Real Purview / ICAP integration (PoC stubs only in v1)
- LLM-judge tuning and FP/FN benchmarks (v1.1)
- Code-block-aware detection thresholds (v1.1)

See `docs/research-notes.md` section 11 for the full deferred list.
