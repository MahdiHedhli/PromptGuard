# PromptGuard Architecture

The architectural argument for PromptGuard: how it is put together, and the load-bearing reasoning behind each piece. This document consolidates the v1 design decisions into a single argument; per-decision detail lives in `decisions/`.

---

## 1. The picture

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
                   |  Regex           |  +-----------------+
                   |  OPF (HTTP)      |          ^
                   |  Presidio (HTTP) |          |
                   |  LLM judge (off) |          |
                   +------------------+          |
                            |                    |
                            v                    |
                   +------------------+          |
                   |   ActionEngine   |          |
                   |   BLOCK / MASK / |----------+
                   |   TOKENIZE       |
                   +------------------+
                            ^
                            |
                   +------------------+
                   |  PolicyAdapter   |
                   |  (LocalYAML)     |
                   +------------------+
```

## 2. Components

### LiteLLM proxy (edge)

LiteLLM is the entry point. It exposes Anthropic and OpenAI-compatible endpoints on `localhost:4000`. PromptGuard plugs in as pre-call and post-call hooks (custom callbacks), giving us control over both the outbound payload and the streamed response.

### DetectionPipeline (core)

A small orchestrator that fans a payload out to every configured detector and aggregates their outputs into a list of `Detection` objects. Detectors run independently. Any detector flagging a span is sufficient to trigger the policy-mapped action.

### Detectors

| Detector             | What it catches                                                                                       | Where it runs                  |
|----------------------|-------------------------------------------------------------------------------------------------------|---------------------------------|
| RegexDetector        | Structured secrets: PEM keys, AWS / GCP / Azure credentials, DB URLs, JWTs, RFC 1918, domains, emails | In-process                      |
| OPFDetector          | Context-aware PII: names, addresses, phones, free-form secrets                                        | HTTP to `opf-service` container |
| PresidioDetector     | Org-specific custom recognizers                                                                       | HTTP to Presidio analyzer       |
| LLMJudgeDetector     | Paraphrased / adversarial reformulations (off by default)                                             | HTTP to local Ollama            |

### ActionEngine

Maps each `(span, category, confidence)` to a policy decision (BLOCK, MASK, or TOKENIZE) and rewrites the payload accordingly. For TOKENIZE, allocates a per-conversation token from a CSPRNG-backed namespace and records the mapping.

### TokenRestorer

Streams the LLM response, scans for tokens issued during pre-call, and substitutes the originals back. Operates at SSE event granularity to preserve event count and content-block index across the rewrite.

### Policy sources

| Adapter             | Status (v1)                | What it does                                  |
|---------------------|----------------------------|-----------------------------------------------|
| LocalYAMLPolicy     | Reference, default         | Reads `policies/<name>.yaml`                  |
| GitManifestPolicy   | Adapter framework only     | Pulls signed manifests from a Git repo        |
| PurviewDLPPolicy    | PoC stub + sample import   | Translates Microsoft Purview SITs to PG rules |
| ICAPPolicy          | PoC stub + sample fixtures | Routes scan requests through an ICAP server   |

## 3. Data flow, end to end

1. AI tool sends a request to `http://localhost:4000`.
2. LiteLLM invokes the pre-call hook with the payload.
3. `DetectionPipeline` runs every configured detector against the prompt.
4. `ActionEngine` reads the active `Policy` and decides per-span: BLOCK, MASK, or TOKENIZE.
5. If anything is BLOCKed, the request is rejected with a structured error and the audit log is written.
6. Otherwise, the rewritten payload is forwarded upstream.
7. LiteLLM streams the response back; the post-call hook pipes it through `TokenRestorer`, which substitutes original values back into the response in real time.
8. The audit log records: detections, actions, policy version, conversation ID. Original values are never persisted.

## 4. Containers

`docker-compose.yml` brings up three services:

- `litellm`: the proxy, port 4000.
- `presidio-analyzer`: Microsoft Presidio analyzer, internal-only.
- `opf-service`: a thin FastAPI server wrapping the OpenAI Privacy Filter Hugging Face model, internal-only.

OPF runs in its own service rather than in-process for two reasons. First, the model is 1.5B parameters and 3 GB on disk; loading it into the LiteLLM worker would couple proxy startup to model startup, and a model load failure would crash the proxy. Second, FastAPI gives us a clean health/ready boundary so docker-compose `--wait` actually waits for OPF to be usable, not just for its TCP socket to bind.

The Presidio anonymizer is deliberately not used. Presidio's anonymization vocabulary does not cleanly express our `BLOCK`/`MASK`/`TOKENIZE` semantics. In particular, reversible TOKENIZE with per-conversation scope and unguessable token IDs is not Presidio's model. We use Presidio's analyzer for org-specific custom recognizers and apply our own action engine on top.

## 5. Load-bearing design decisions

### 5.1 Multi-stage detection, not one classifier

Regex catches structured shapes (PEM keys, cloud credentials, JWTs, DB URLs, RFC 1918) deterministically and at zero per-request cost. OPF catches context-aware PII the regex layer cannot see by shape (names, addresses, free-form secrets). Presidio carries the org-specific custom recognizers an enterprise team will inevitably need (codenames, customer names, internal hostnames). The LLM judge is a paraphrase backstop, off by default.

This is structural: no single detector is sufficient. Tonic.ai's published OPF benchmark on AI4Privacy shows OPF default-operating-point recall around 0.10 on out-of-distribution web crawls. The regex layer covers exactly the categories OPF underperforms on at default operating points; OPF covers exactly what regex cannot see by shape. Each layer is calibrated against what the others miss.

### 5.2 Per-action classes; engine is a dispatcher

`ActionEngine` does not contain BLOCK/MASK/TOKENIZE logic. It groups detections by policy-resolved action into three buckets, then dispatches each bucket to a dedicated `BlockAction`, `MaskAction`, or `TokenizeAction`. BLOCK short-circuits the rewrite. MASK and TOKENIZE both rewrite by span and are merged into a single right-to-left pass over their union.

The dispatcher shape lets each action be reasoned about, tested, and changed independently. Adding a new action class (for example, REDACT-WITH-HASH) does not require touching the engine. The engine's only job is bucketing and ordering.

Span overlap across detectors is solved by a longest-first greedy non-overlapping selection (`_select_outer_spans`). When regex and Presidio both flag the same IP, or when OPF emits two adjacent fragments for one email, the longest span wins and shorter overlapping spans are dropped. This is the right behavior because a JWT replaced as one token reads more cleanly than a JWT with its middle masked out as a separate secret span.

### 5.3 NUL-bracketed boundary concatenation for JSON-safe substitution

Anthropic and OpenAI request bodies are JSON. A naive "rewrite each `messages[i].content` field separately" loop fans the detection pipeline out per-field and runs the cost N times for an N-message conversation. The chosen approach concatenates all inspectable strings with a `\x00\x00PG_BOUNDARY\x00\x00` separator, runs detection + rewrite once over the joined text, then splits and writes back to the original paths. The boundary contains NULs that no prompt or detector regex can match, and ASCII text that any JSON encoder passes through verbatim.

Inspected paths are explicit: `messages[i].content` (string or structured-block text), Anthropic's nested `tool_result` content, and `system` (string or structured). Tool definitions are not inspected; a tool description that mentions a credential category is the operator's intent.

### 5.4 Random unguessable tokens, format `[CATEGORY_<16hex>]`

Tokens are issued by `secrets.token_hex(8)` (64 bits). The threat is unguessability, not collision: an upstream model that emits a string shaped like our token must not cause us to invent a mapping that pulls original PII back into the response. Sequential or low-entropy tokens (`[EMAIL_001]`) make this attack trivial; 64 bits of CSPRNG output makes it economically equivalent to guessing a symmetric key.

The reverse-path regex is `\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]`. The 16-or-more form lets us grow tokens without breaking historical traffic; we never shrink. Hex contains no characters that need JSON escaping, so the bracket-delimited form survives every encoder we hit.

### 5.5 Per-conversation TokenMap with TTL + LRU eviction

Tokens are scoped per conversation. Conversation A cannot see conversation B's tokens: a conversation B response containing a token shape from A will pass through unrestored, by design. Threat-model A7 (LLM emits a token-shaped string we did not issue) is closed by this scope.

The map has a 1-hour TTL per conversation and a 100-conversation LRU cap. Both bounds are deliberate. TTL prevents indefinite retention of original PII in memory. LRU prevents a long-running daemon from accumulating maps without bound. Crossing either bound evicts the conversation's entire map; subsequent requests in that conversation get fresh tokens, which matches the privacy promise (no cross-session linking).

### 5.6 SSE rebuild at content-block granularity, not byte-level

LiteLLM hands us streaming responses as a single buffered SSE blob in some configurations and as per-event chunks in others. The restorer parses the SSE into structured events, restores tokens within each `content_block_delta`'s text field, and re-emits each event preserving its original `event:` line, `index`, and sibling fields. This is what claude CLI v2.x's extended-thinking path needs: text blocks live at non-zero indexes, and hardcoding `index: 0` on rebuild produces the visible "Content block is not a text block" error.

The byte-level and per-event restorer primitives (`StreamingRestorer`, `SSEStreamRestorer`) are kept in the codebase because they are correct for genuinely-per-event streams. The iterator hook picks the right tool based on chunk shape.

### 5.7 Allow LiteLLM requests when the audit DB is unavailable

`/v1/messages?beta=true` is what claude CLI v2.x posts. LiteLLM's auth path requires a `database_url` to be configured, even when no audit DB is present. Setting `allow_requests_on_db_unavailable: true` lets the proxy serve traffic when the DB is not configured. Our audit log writer is an independent JSONL sink (next section); LiteLLM's audit DB is not on the critical path.

### 5.8 JSONL audit with structural no-text invariant

The audit log is a JSONL file with one event per line: timestamp, conversation ID, request ID, rule, detector, category, span offset and length, action taken, pipeline version, policy hash, confidence. Crucially, the original PII text is never in the log. A 200-iteration fuzz test asserts this structurally: it generates random PII, runs the engine, parses every emitted event, and asserts no field contains the input text.

This is what lets the audit log be shipped to a SIEM or operator without becoming a new PII surface. Compare to "log the detection with the matched span" approaches that turn the audit trail into the very thing PromptGuard exists to prevent.

### 5.9 Per-rule audit-only override

The default policy mode is "every rule enforces." Operators promoting a new rule from "I think this catches X" to "this is enforced for everyone" need a window where the rule fires and is logged but does not block or rewrite. Per-rule `audit_only: true` gives them that. The engine emits audit events for audit-only detections regardless of whether enforcement also fires, so the typical operator workflow (audit-only one rule for a soak window, then promote) accumulates events even on requests other rules block.

### 5.10 LLM judge is opt-in with tolerant runtime semantics

The LLM judge posts to a local Ollama at `temperature: 0`, `seed: 0`, with a structured prompt asking for a JSON array of `{category, start, end}`. Failure modes return zero detections with a warning log: timeout, HTTP error, connection refused, non-JSON envelope, malformed list items, out-of-range spans. The judge is opt-in via `detectors.llm_judge.enabled: true` because the v1 default model produces unreliable JSON; an operator who turns it on with an unreliable model gets no false positives, just no judge-derived detections.

The judge's status as v1 was "wired but not validated against a benchmark." Validating or removing this component is a v1.1 work item.

### 5.11 Adapter ABCs, not Protocols

`DetectorAdapter` and `PolicyAdapter` are real ABCs with audit-conformance tests. Every shipped adapter is parametrized through a single conformance test that asserts class-attribute conventions (lowercase `name`, no spaces), output shape invariants, and ABC subclassing. Protocols would document the shape but not enforce it; ABCs let an adapter's instantiation refuse at construction time when the contract is not met. The v1 LLM judge skeleton, before its real implementation landed, raised `LLMJudgeNotImplemented` from its constructor for exactly this reason.

This is what lets `PurviewDLPPolicy` and `ICAPPolicy` ship as PoC stubs with sample fixtures: the adapter ABCs are the contract real integrations will satisfy when they land.

## 6. What is deliberately out of scope at v1

- Centralized proxy mode for mobile users (v1.1).
- Browser extension (v1.1 / v2). The local proxy intercepts API traffic only; browser-based ChatGPT / Claude.ai requires a different intercept path.
- Image and file scanning. v1 inspects text only; image / file content scanning is v1.x.
- Real Microsoft Purview Graph API and ICAP server integration. v1 ships the adapter ABCs and PoC fixtures; real network calls land later.
- Code-block-aware detection thresholds. v1 treats all text uniformly.
- Per-request policy override (e.g., `x-promptguard-policy: pentest-engagement`). The threat model rejects per-request overrides as too easy to abuse.
- Audit log rotation. v1 has the writer; rotation is the operator's concern (logrotate works on the JSONL file).
- TokenMap durability across process restart. Threat-model A6 says intentionally not durable; may revisit if multi-tenant server mode is added.
