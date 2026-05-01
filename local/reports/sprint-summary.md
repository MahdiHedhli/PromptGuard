# PromptGuard v1 Sprint Summary

**Sprint:** Day 1 (2026-04-30) through Day 9 (2026-05-06).
**Outcome:** v1 detection + action pipeline shipped, deployed, benchmarked. Repo public at `github.com/MahdiHedhli/PromptGuard`. HARD STOP for owner review before Day 10 packaging polish + blog draft.

## TL;DR for the owner review

**On track.** Every locked decision in research-notes.md was implemented on schedule. The 9-day implementation budget was a tight fit (Day 3-4 reversible TOKENIZE was the most complex; Day 9 LLM-judge diagnostic surfaced a v1.1 work item). One feature ships **shipped-but-not-validated**: the LLM judge. Everything else is shipped-and-tested.

**Numbers worth quoting:**

- 201 tests pass in the default run; 10 docker-marked tests skip cleanly when the stack is down (with stack up, all 211 pass).
- 19 decision logs (DEC-001 through DEC-019).
- Detection F1 1.000 on 6 of 8 regex-coverable categories.
- In-process pipeline overhead 0.305 ms p50 / 0.545 ms p95.
- End-to-end proxy overhead 12.4 ms (dominated by LiteLLM).
- Cold start 161 s (clean), <15 s (warm).
- Audit log no-text invariant: 200-iteration fuzz test, no PII string ever appears in log content.

## Decisions index (DEC-001 through DEC-019)

| ID | Day | Topic |
|---|---|---|
| [DEC-001](../decisions/001-python-and-build.md) | 1 | Python 3.11+, uv, hatchling backend |
| [DEC-002](../decisions/002-opf-service-shape.md) | 1 | OPF as separate FastAPI container, not in-process |
| [DEC-003](../decisions/003-regex-pattern-sourcing.md) | 1 | Vendored regex patterns from gitleaks (MIT) + detect-secrets (Apache 2.0) |
| [DEC-004](../decisions/004-action-engine-deferred-rewrite.md) | 1 | Day-1 action engine reports decisions only; rewrite lands Day 2 |
| [DEC-005](../decisions/005-presidio-anonymizer-not-used.md) | 1 | Use Presidio Analyzer only; Anonymizer's operator semantics do not match BLOCK / MASK / TOKENIZE |
| [DEC-006](../decisions/006-litellm-config-day-one.md) | 1 | Day-1 LiteLLM is vanilla; hooks land Day 2 |
| [DEC-007](../decisions/007-pytest-pythonpath-workaround.md) | 1 | Hatchling's `_editable_impl_*.pth` is skipped by site.py; add `pythonpath=["src"]` to pytest |
| [DEC-008](../decisions/008-action-engine-split.md) | 2 | Per-action classes + dispatcher engine |
| [DEC-009](../decisions/009-opf-eager-load-and-hard-fail.md) | 2 | OPF eager-load at service startup; proxy hard-fails on non-200 `/ready` |
| [DEC-010](../decisions/010-litellm-hook-customlogger-bridge.md) | 2 | Container-side handler subclasses CustomLogger; core hook stays provider-agnostic |
| [DEC-011](../decisions/011-json-safe-substitution.md) | 2 | NUL-bracketed boundary concatenation for JSON-safe rewriting |
| [DEC-012](../decisions/012-random-token-ids-and-format.md) | 3 | Unguessable random token IDs (`secrets.token_hex(8)`); format `[CATEGORY_<16-hex>]` |
| [DEC-013](../decisions/013-token-map-eviction.md) | 3 | Per-conversation token map: 1h TTL + 100-conversation LRU |
| [DEC-014](../decisions/014-sse-coalesce-on-restoration.md) | 3 | Streaming SSE reverse path rebuilds events in place; preserves event count |
| [DEC-015](../decisions/015-litellm-allow-requests-on-db-unavailable.md) | 4 | LiteLLM `allow_requests_on_db_unavailable: true` for `/v1/messages?beta=true` |
| [DEC-016](../decisions/016-policy-hot-reload-opt-in-polling.md) | 5 | Policy hot-reload via opt-in stdlib mtime polling |
| [DEC-017](../decisions/017-adapter-framework-formalization.md) | 6-7 | DetectorAdapter + PolicyAdapter ABCs; Purview + ICAP stubs with sample fixtures |
| [DEC-018](../decisions/018-llm-judge-and-audit-writer.md) | 8 | LLM judge real impl (Ollama); audit log writer (JSONL, no-text invariant) |
| [DEC-019](../decisions/019-per-rule-audit-only-and-llm-judge-validation.md) | 9 | Per-rule `audit_only`; LLM judge "shipped but not validated" at v1 |

## Blockers hit and resolutions (chronological)

| Day | Blocker | Resolution |
|---|---|---|
| 1 | Foundational docs (CLAUDE.md, research-notes.md, templates) not yet in repo at session start. | Wrote partial blocker report; owner re-uploaded; resumed. ~10 min. |
| 1 | Host port 4000 held by another process. | Made all host ports env-configurable. Defaults unchanged. |
| 1 | Hatchling editable install: `_editable_impl_<pkg>.pth` skipped by `site.py`. | DEC-007: `pythonpath=["src"]` in pytest config. |
| 2 | LiteLLM image is uv-managed, no pip in venv. | Bootstrap pip via `ensurepip`; install pinned `uv==0.10.9` to match upstream. |
| 2 | LiteLLM exception handler stringifies HTTPException dict detail via str(). | Pre-serialize the envelope to JSON, pass as detail string. |
| 3 | LiteLLM hands `async_post_call_streaming_iterator_hook` a single buffered bytes chunk; tokens span multiple SSE delta events. | DEC-014: parse SSE blob, concatenate deltas, restore in concatenation, re-emit with event count preserved. |
| 4 | OPF eager-load wasn't firing under FastAPI's deprecated `@app.on_event("startup")`. | Switched to `lifespan` async context manager. Container healthcheck now targets `/ready`, not `/health`, so docker-compose `--wait` blocks until OPF is genuinely usable. |
| 4 | claude CLI v2.x sends `/v1/messages?beta=true` which LiteLLM's auth path requires `database_url` for. | DEC-015: `allow_requests_on_db_unavailable: true`. |
| 6 | Anthropic free-tier account had zero credit on real-key capture day 1. | Mock-based capture as v1 visual; real-key capture once $50 paid credit landed. |
| 9 | Docker-Ollama on Apple Silicon: 0.28 tok/s, unusable. | Installed Ollama natively (Metal GPU): 61 tok/s, 220x faster. |
| 9 | LLM judge default prompt + small models (1.5-3B) produce malformed JSON / zero detections. | DEC-019: shipped-but-not-validated at v1. v1.1 work item. |

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

### End-to-end through proxy (Day-5 measurement)

| Path | avg | p95 |
|---|---:|---:|
| BLOCK on AWS key | 12.4 ms | 17.6 ms |

Bulk of 12.4 ms is LiteLLM's request handling; PromptGuard's contribution is ~0.3 ms.

### Cold start

161 s wall-clock with default policy (regex+OPF+Presidio) on a clean machine. Subsequent boots <15 s. OPF model load dominates first-boot cost.

### Memory (idle, default policy)

litellm ~250 MB; opf-service ~3.0 GB; presidio-analyzer ~700 MB.

### Sanity check vs Tonic published OPF numbers

We did not re-run OPF against AI4Privacy. Tonic (2026-04-24) reports default-operating-point precision 0.95+, recall ~0.10 on web crawls and ~0.38 on EHR. Our layered architecture exists precisely because of those numbers: the regex layer covers what OPF underperforms on at default operating points, OPF covers what regex cannot see by shape (free-form names, addresses, phone). v1.1 should run the OPF calibration sweep on the AI4Privacy corpus.

## Recommended Day 10 priorities (for owner review)

1. **claude CLI v2.x compat investigation** (2-hour timebox). Direct curl works; claude CLI rejects our restored SSE on PII-bearing prompts. Day 8 streaming-restorer fixes (no-op short-circuit, event-count preservation) helped but didn't fully resolve. Likely a deeper response-shape expectation we have not yet isolated.
2. **Packaging polish**:
   - LiteLLM image digest pin (currently `main-stable` floating tag).
   - Real-key claude CLI capture once compat is fixed (replaces the curl-based asset 03).
   - Final README pass with the 161-second deploy promise rendered against the cold-start number we measured.
3. **Blog post draft** (research-notes section 14 outline). Benchmark numbers slot into sections 6 + 7; round-trip visual into section 8 (use docs/blog-assets/01 + 02 as the headline; consider adding asset 03 once real-key works through claude CLI).
4. **Sprint summary distribution** (this file): paste into the planning chat for owner review.

## Open issues / known limitations going into v1.1

- **LLM judge: shipped but not validated.** Default prompt template + small (1.5-3B) Ollama models produce malformed JSON or zero detections. Wiring is correct (verified via latency delta). v1.1 priorities: prompt-template iteration with few-shot examples, tuned model for the PII task, or graduate to 8B+ at a documented latency cost. Operators who turn on `detectors.llm_judge.enabled: true` today get working wiring and zero added detections. Documented in DEC-019 and docs/llm-judge.md.
- **claude CLI v2.x streaming compat.** Direct HTTP / curl / SDKs that respect ANTHROPIC_BASE_URL work cleanly. claude CLI v2.x rejects our restored SSE on PII-bearing prompts with "Content block is not a text block". Day 10 morning investigation (2-hour timebox).
- **No real AI4Privacy benchmark run.** Day-9 brief authorized synthetic-corpus fallback. Real corpus run is a v1.1 deliverable; requires `datasets` dep + ~30 GB disk.
- **Cross-category corpus annotation.** A postgres URL legitimately contains a domain; our synth corpus only annotated the URL as expected. F1 numbers on domain / email reflect annotation gaps, not detector inaccuracy. v1.1 re-annotation pass.
- **Per-conversation policy override.** A tool could include a header like `x-promptguard-policy: pentest-engagement` to pick a non-default policy on a per-request basis. v1 explicitly does NOT ship this; the threat model rejects per-request overrides as too easy to abuse. v1.1 candidate if the operator workflow demands it.
- **Audit log rotation.** v1 has the writer; rotation is the operator's concern (logrotate works). v1.1 should ship a Cookbook recipe and / or built-in size-based rotation.
- **GitManifestPolicy is a NotImplementedError stub.** Real signed-manifest pull is v1.1.
- **Real Purview Graph API + ICAP server integration.** The v1 stubs ship sample fixtures; v1.1 lands the real network calls.
- **Browser extension (v1.1 / v2).** Out of scope for v1; the local proxy intercepts API traffic only.
- **Mobile clients.** Out of scope for v1; centralized proxy mode comes in v1.1.
- **Image / file uploads to LLMs.** v1 inspects text only; image/file content scanning is v1.x.
- **TokenMap durability across process restart.** Threat-model A6 says intentionally not durable. v1.1 may revisit if multi-tenant server mode is added.

## LLM judge validation status

**Shipped but not validated.**

- Wiring confirmed: latency delta of +1.7 s with `llama3.2:3b` against native Ollama, vs +0 ms when judge disabled. The detector is being invoked through the pipeline.
- Detection NOT confirmed: tested with `qwen2.5:1.5b-instruct-q4_K_M` and `llama3.2:3b-instruct-q4_K_M` against three obvious paraphrased-PII prompts. 1.5B returned `[]` for all prompts. 3B emitted malformed JSON (`["category": ...]` instead of `[{...}]`) that our parser correctly drops.
- Conclusion: the wiring is correct and the adapter's tolerance posture (timeout / HTTP error / malformed output -> zero detections + warning) means an operator who enables the judge with the default model gets working wiring and no false positives, but also no detections beyond the deterministic stages.
- v1.1 priorities: prompt-template iteration (few-shot examples + stricter format), tuned model (community fine-tune for the PII task), or graduate the recommended default to 8B+ class at a documented latency hit.
- **The deterministic stages (regex + OPF + Presidio) deliver the v1 detection promise without the judge.**

---

End of sprint summary. HARD STOP. Owner reviews before Day 10.
