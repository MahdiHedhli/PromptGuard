# PromptGuard v1 decisions log

A compact index of every decision made during the v1 build, with the numbers that came out the other side.

## Numbers worth quoting

- 201 tests pass in the default run; 10 docker-marked tests skip cleanly when the stack is down (with stack up, all 211 pass).
- 19 decision logs (DEC-001 through DEC-019).
- Detection F1 1.000 on 6 of 8 regex-coverable categories.
- In-process pipeline overhead 0.305 ms p50, 0.545 ms p95.
- End-to-end proxy overhead 12.4 ms (dominated by LiteLLM, not PromptGuard).
- Cold start 161 s (clean), under 15 s (warm).
- Audit log no-text invariant: 200-iteration fuzz test, no PII string ever appears in log content.

## Decisions index (DEC-001 through DEC-019)

| ID | Topic |
|---|---|
| [DEC-001](../decisions/001-python-and-build.md) | Python 3.11+, uv, hatchling backend |
| [DEC-002](../decisions/002-opf-service-shape.md) | OPF as separate FastAPI container, not in-process |
| [DEC-003](../decisions/003-regex-pattern-sourcing.md) | Vendored regex patterns from gitleaks (MIT) + detect-secrets (Apache 2.0) |
| [DEC-004](../decisions/004-action-engine-deferred-rewrite.md) | v1 action engine reports decisions only; rewrite ships next |
| [DEC-005](../decisions/005-presidio-anonymizer-not-used.md) | Use Presidio Analyzer only; Anonymizer's operator semantics do not match BLOCK / MASK / TOKENIZE |
| [DEC-006](../decisions/006-litellm-config-day-one.md) | Vanilla LiteLLM at scaffolding; hooks land with the action engine |
| [DEC-007](../decisions/007-pytest-pythonpath-workaround.md) | Hatchling's `_editable_impl_*.pth` is skipped by site.py; add `pythonpath=["src"]` to pytest |
| [DEC-008](../decisions/008-action-engine-split.md) | Per-action classes + dispatcher engine |
| [DEC-009](../decisions/009-opf-eager-load-and-hard-fail.md) | OPF eager-load at service startup; proxy hard-fails on non-200 `/ready` |
| [DEC-010](../decisions/010-litellm-hook-customlogger-bridge.md) | Container-side handler subclasses CustomLogger; core hook stays provider-agnostic |
| [DEC-011](../decisions/011-json-safe-substitution.md) | NUL-bracketed boundary concatenation for JSON-safe rewriting |
| [DEC-012](../decisions/012-random-token-ids-and-format.md) | Unguessable random token IDs (`secrets.token_hex(8)`); format `[CATEGORY_<16-hex>]` |
| [DEC-013](../decisions/013-token-map-eviction.md) | Per-conversation token map: 1h TTL + 100-conversation LRU |
| [DEC-014](../decisions/014-sse-coalesce-on-restoration.md) | Streaming SSE reverse path rebuilds events in place; preserves event count |
| [DEC-015](../decisions/015-litellm-allow-requests-on-db-unavailable.md) | LiteLLM `allow_requests_on_db_unavailable: true` for `/v1/messages?beta=true` |
| [DEC-016](../decisions/016-policy-hot-reload-opt-in-polling.md) | Policy hot-reload via opt-in stdlib mtime polling |
| [DEC-017](../decisions/017-adapter-framework-formalization.md) | DetectorAdapter + PolicyAdapter ABCs; Purview + ICAP stubs with sample fixtures |
| [DEC-018](../decisions/018-llm-judge-and-audit-writer.md) | LLM judge real impl (Ollama); audit log writer (JSONL, no-text invariant) |
| [DEC-019](../decisions/019-per-rule-audit-only-and-llm-judge-validation.md) | Per-rule `audit_only`; LLM judge "shipped but not validated" at v1 |
| [DEC-020](../decisions/020-streaming-restorer-preserve-content-block-index.md) | Streaming restorer preserves content_block index for claude CLI v2.x |
| [DEC-021](../decisions/021-litellm-image-digest-pin.md) | LiteLLM image pinned by SHA-256 digest |
| [DEC-022](../decisions/022-mitm-verification-harness.md) | MITM verification harness positioned between LiteLLM and upstream |
| [DEC-023](../decisions/023-span-overlap-greedy-non-overlap-selection.md) | Greedy longest-first non-overlapping span selection |

## Blockers hit and resolutions

| Blocker | Resolution |
|---|---|
| Host port 4000 held by another process. | Made all host ports env-configurable. Defaults unchanged. |
| Hatchling editable install: `_editable_impl_<pkg>.pth` skipped by `site.py`. | DEC-007: `pythonpath=["src"]` in pytest config. |
| LiteLLM image is uv-managed, no pip in venv. | Bootstrap pip via `ensurepip`; install pinned `uv==0.10.9` to match upstream. |
| LiteLLM exception handler stringifies HTTPException dict detail via str(). | Pre-serialize the envelope to JSON, pass as detail string. |
| LiteLLM hands `async_post_call_streaming_iterator_hook` a single buffered bytes chunk; tokens span multiple SSE delta events. | DEC-014: parse SSE blob, concatenate deltas, restore in concatenation, re-emit with event count preserved. |
| OPF eager-load wasn't firing under FastAPI's deprecated `@app.on_event("startup")`. | Switched to `lifespan` async context manager. Container healthcheck targets `/ready`, not `/health`. |
| claude CLI v2.x sends `/v1/messages?beta=true` which LiteLLM's auth path requires `database_url` for. | DEC-015: `allow_requests_on_db_unavailable: true`. |
| Anthropic free-tier had zero credit on real-key capture day. | Mock-based capture as initial visual; real-key capture once credit was provisioned. |
| Docker-Ollama on Apple Silicon: 0.28 tok/s, unusable. | Installed Ollama natively (Metal GPU): 61 tok/s, 220x faster. |
| LLM judge default prompt + small models (1.5-3B) produce malformed JSON / zero detections. | DEC-019: shipped-but-not-validated at v1. v1.1 work item. |

## Final benchmark numbers (calibration footnotes)

### Detection (synthetic corpus, 220 examples, regex layer)

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| cloud_api_key | 1.000 | 1.000 | 1.000 |
| database_url | 1.000 | 1.000 | 1.000 |
| domain | 0.333 | 1.000 | 0.500 [^a] |
| email | 0.500 | 1.000 | 0.667 [^a] |
| internal_ip | 1.000 | 1.000 | 1.000 |
| jwt | 1.000 | 1.000 | 1.000 |
| private_key | 1.000 | 1.000 | 1.000 |
| secret | 1.000 | 1.000 | 1.000 |

[^a]: domain and email FP rates reflect cross-category overlap with database_url and JWT spans, NOT detector inaccuracy. A postgres URL legitimately contains a domain; the synth corpus only annotated the URL as the "expected" span. v1.1 includes a re-annotation pass that marks every valid span per example.

### Latency (in-process, n=1000, 305-char prompt)

| Configuration | avg | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| Baseline regex only | 0.146 ms | 0.069 ms | 0.182 ms | 1.671 ms |
| Pipeline + engine | 0.305 ms | 0.298 ms | 0.545 ms | 1.008 ms |
| Pipeline + engine + audit-only | 0.606 ms | 0.316 ms | 0.911 ms | 3.469 ms |

### End-to-end through proxy

| Path | avg | p95 |
|---|---:|---:|
| BLOCK on AWS key | 12.4 ms | 17.6 ms |

Bulk of the 12.4 ms is LiteLLM's request handling; PromptGuard's contribution is around 0.3 ms.

### Cold start

161 s wall-clock with default policy (regex + OPF + Presidio) on a clean machine. Subsequent boots under 15 s. OPF model load dominates first-boot cost.

### Memory (idle, default policy)

litellm ~250 MB; opf-service ~3.0 GB; presidio-analyzer ~700 MB.

### Sanity check vs Tonic published OPF numbers

We did not re-run OPF against AI4Privacy. Tonic.ai (2026-04-24) reports default-operating-point precision 0.95+, recall around 0.10 on web crawls and around 0.38 on EHR. Our layered architecture exists precisely because of those numbers: the regex layer covers what OPF underperforms on at default operating points, and OPF covers what regex cannot see by shape (free-form names, addresses, phone numbers).

## Open issues / known limitations going into v1.1

- **LLM judge: shipped but not validated.** Default prompt template + small (1.5-3B) Ollama models produce malformed JSON or zero detections. Wiring is correct (verified via latency delta). v1.1 priorities: prompt-template iteration with few-shot examples, tuned model for the PII task, or graduate to 8B+ at a documented latency cost. Documented in DEC-019 and `docs/llm-judge.md`.
- **No real AI4Privacy benchmark run.** Synthetic-corpus fallback in v1; real corpus run is a v1.1 deliverable; requires `datasets` dep + ~30 GB disk.
- **Cross-category corpus annotation.** A postgres URL legitimately contains a domain; the synth corpus only annotated the URL as expected. F1 numbers on domain / email reflect annotation gaps, not detector inaccuracy. v1.1 re-annotation pass.
- **Per-conversation policy override.** A tool could include a header like `x-promptguard-policy: pentest-engagement` to pick a non-default policy on a per-request basis. v1 explicitly does NOT ship this; the threat model rejects per-request overrides as too easy to abuse. v1.1 candidate if the operator workflow demands it.
- **Audit log rotation.** v1 has the writer; rotation is the operator's concern (logrotate works). v1.1 should ship a Cookbook recipe and / or built-in size-based rotation.
- **GitManifestPolicy is a NotImplementedError stub.** Real signed-manifest pull is v1.1.
- **Real Purview Graph API + ICAP server integration.** The v1 stubs ship sample fixtures; v1.1 lands the real network calls.
- **Browser extension (v1.1 / v2).** Out of scope for v1; the local proxy intercepts API traffic only.
- **Mobile clients.** Out of scope for v1; centralized proxy mode comes in v1.1.
- **Image / file uploads to LLMs.** v1 inspects text only; image/file content scanning is v1.x.
- **TokenMap durability across process restart.** Threat-model A6 says intentionally not durable. v1.1 may revisit if multi-tenant server mode is added.
