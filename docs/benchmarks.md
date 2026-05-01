# PromptGuard benchmarks

## TL;DR

* **Detection F1 on the structured-secret categories is 1.0** under the regex layer alone (PEM private keys, AWS / GCP / Azure credentials, JWTs, RFC-1918 IPs, GitHub PATs, database URLs). These are the categories CISOs lose sleep over; they are the categories where deterministic detection is the right tool.
* **Per-request in-process overhead is ~0.3 ms p50 / 0.5 ms p95** for the full DetectionPipeline + ActionEngine + JSON-safe rewrite. That's well under the +5 ms budget the threat-model conversation tolerates.
* **Audit writer adds ~0.3 ms** on top, dominated by JSONL file I/O. Audit-only policies are still sub-millisecond at p95.
* **Cold-start with default policy**, regex+OPF+Presidio, on a clean machine: **161 seconds** wall-clock to all-services-healthy. Subsequent boots reuse the cached OPF model and complete in seconds.
* **End-to-end through the proxy** adds a further ~12 ms fixed overhead. The bulk of that is LiteLLM, not PromptGuard.

## Methodology

### Corpus

We use a synthetic corpus of 220 examples (160 positive across 8 detector-coverable categories, 60 negative-control prompts). the v1 plan authorized this fallback because the AI4Privacy PII-Masking-300k corpus on Hugging Face requires the `datasets` package and an authenticated download path that did not fit the v1 budget. Tonic's published numbers on AI4Privacy serve as the external sanity check; we do not re-run their evaluation on the same corpus.

The synthetic corpus is generated locally by `benchmarks/run_detection_benchmarks.py::_synth_corpus()`. Each positive example is structured as `<prefix><PII span><suffix>` so the expected span position is known at construction time. Negative examples are plain prose containing no PII shapes.

### Detector layers

The numbers below are for the regex layer running in isolation. OPF and Presidio require running services and are benchmarked separately when the docker stack is up. The LLM judge is **shipped but not validated at v1** (see [DEC-019](../decisions/019-per-rule-audit-only-and-llm-judge-validation.md)): wiring works end-to-end, but the default prompt template + small (1.5-3B) local Ollama models do not produce reliably-shaped JSON output. v1.1 work item.

### Latency

In-process measurements on Apple Silicon CPython 3.11. Each configuration runs n=1000 with a 305-char prompt containing 5 distinct PII spans (email, IP, DB URL, JWT, AWS key). End-to-end-through-proxy numbers come from the v1 measurement and are dominated by LiteLLM's request handling, not PromptGuard's overhead.

### Honesty notes

* **Synthetic-corpus framing.** Numbers below come from a corpus we generated. The shapes match real-world examples (gitleaks rules, detect-secrets fixtures), but the corpus is small and not adversarially constructed. Tonic's AI4Privacy numbers, which we do NOT re-run here, would give a more conservative recall estimate especially on the OPF layer.
* **Cross-category overlap.** A postgres URL like `postgres://user:p@db.example.com/app` matches both the database_url category AND the domain category. Our scoring treats the domain hit as a "false positive for domain" because the synth corpus only declared the URL span as expected. Real evaluation in v1.1 should annotate ALL valid spans per example.
* **OPF / Presidio not measured here.** Their HTTP-hop costs are characterized below from v1 instrumentation, not from a corpus run.
* **No real-time corpus run against AI4Privacy.** Authorized fallback per the v1 plan.

## Detection results

Synthetic corpus, regex layer, n=220.

| Category | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| cloud_api_key | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |
| database_url | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |
| domain | 0.333 | 1.000 | 0.500 | 20 | 40 | 0 |
| email | 0.500 | 1.000 | 0.667 | 20 | 20 | 0 |
| internal_ip | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |
| jwt | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |
| private_key | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |
| secret | 1.000 | 1.000 | 1.000 | 20 | 0 | 0 |

**Reading the table:**

* Six of eight categories at perfect F1 (PEM keys, AWS/GCP/Azure creds, JWTs, RFC-1918 IPs, DB URLs, GitHub PATs/secrets). Recall 1.0 means the regex layer never missed an example we synthesized; precision 1.0 means it never flagged a non-example.
* The two categories with reduced apparent F1 (domain, email) are reduced by cross-category overlap, not by detector failure. Database URLs and JWTs both contain substrings that legitimately match the email and domain regexes. This is a corpus-annotation artifact: a more honest scoring would mark every valid PII span per example, not just the "primary" one. v1.1 includes the proper annotation pass.
* The detector itself is doing the right thing in those FP-flagged cases: a database URL DOES contain a domain. The action engine's overlap-handling (DEC-008 `_select_outer_spans`) keeps the outer (more specific) span when both fire, so the operator-visible behavior is correct: the URL gets BLOCKed, not the inner domain TOKENIZEd.

## OPF + Presidio: why no live corpus numbers

Tonic's published OPF benchmark on AI4Privacy PII-Masking-300k (2026-04-24) reported:

* default operating point: precision 0.95+, recall 0.10 on web-crawl OOD data
* default operating point: recall 0.38 on EHR OOD data
* recall calibration via Viterbi decoding lifts these substantially

Our v1 design point is "regex catches shapes deterministically; OPF catches context-aware paraphrase; Presidio catches org-specific custom recognizers." The Tonic numbers are why the layered architecture exists: no single detector is sufficient. For v1, we cite Tonic without re-running.

In dev testing across this sprint, OPF (loaded against `openai/privacy-filter`) consistently flagged emails embedded in conversational prose ("ping noreply@example.com tomorrow") that the regex layer also catches via shape. We did not encounter cases where the regex layer caught something OPF missed; OPF's value-add at v1 is in the categories the regex layer cannot see by shape alone (private_name, private_address, free-form personal phone).

## Latency results

### In-process (n=1000, 305-char prompt)

| Configuration | avg | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| baseline_regex_only | 0.146 ms | 0.069 ms | 0.182 ms | 1.671 ms |
| regex_engine_enforce | 0.305 ms | 0.298 ms | 0.545 ms | 1.008 ms |
| regex_engine_audit_only | 0.606 ms | 0.316 ms | 0.911 ms | 3.469 ms |

Engine + JSON-safe extract / rewrite overhead: +0.159 ms avg.
Audit writer overhead (JSONL file I/O): +0.301 ms avg.

### Through the proxy (v1 measurement)

| Path | avg | p95 | p99 |
|---|---:|---:|---:|
| BLOCK on AWS key | 12.4 ms | 17.6 ms | 17.6 ms |

The bulk of the 12 ms is LiteLLM's request handling, not PromptGuard. The PromptGuard hook contribution is the in-process number above (~0.3 ms).

### Cold start

`docker compose up -d --wait` from clean state (no OPF model cache):

* **161 seconds** to all three services healthy with default policy.
* Of that, ~150 seconds is OPF model download and load; ~10 seconds is LiteLLM startup; presidio-analyzer is healthy in ~30 seconds.
* Subsequent boots (cached volume) complete in <15 seconds.

### Memory footprint

Idle stack (default policy, all three services):

* litellm:           ~250 MB RSS
* opf-service:       ~3.0 GB RSS (OpenAI Privacy Filter is 1.5B params, loaded at init)
* presidio-analyzer: ~700 MB RSS

Under load (regex + OPF + Presidio invoked once per second), no measurable RSS growth across a 30-minute soak. Audit log file grows linearly with detection count; rotation is the operator's choice.

## Comparing to "bare LiteLLM with native pattern matching" (Rama's setup)

Rama's blog post sets up LiteLLM with built-in PII guards, configured per-pattern, no rewriting / token-restoration. Conceptual comparison:

| Capability | Rama's v0 | PromptGuard v1 |
|---|:---:|:---:|
| Regex-pattern detection | Yes | Yes (vendored from gitleaks + detect-secrets) |
| Multi-stage layered detection | No | Yes (regex + OPF + Presidio + LLM judge) |
| Reversible TOKENIZE | No | Yes (per-conversation map, streaming SSE round-trip) |
| BLOCK error envelope (Anthropic + OpenAI shape) | No | Yes |
| Per-rule policy granularity | Limited | Yes (BLOCK / MASK / TOKENIZE per category, per-rule audit_only) |
| Adapter framework (DLP integrations) | No | Yes (LocalYAML, Purview-stub, ICAP-stub) |
| Audit log with structural no-text invariant | No | Yes (JSONL, 200-iteration fuzz test) |
| Hot reload with policy validation | No | Yes (DEC-016) |

The numbers above are PromptGuard's; we did not re-run Rama's setup against the same corpus. The capability gap is structural: Rama's setup ships v0 of "intercept and reject"; PromptGuard v1 ships the policy-source-aware, reversible, audit-trail-aware version that an enterprise security team can actually deploy.

## Re-running the benchmarks

```bash
# Detection (synthetic corpus, regex layer)
PYTHONPATH=src .venv/bin/python benchmarks/run_detection_benchmarks.py

# Latency matrix
PYTHONPATH=src .venv/bin/python benchmarks/run_latency_matrix.py

# v1 -> v1 latency progression (older script kept for traceability)
PYTHONPATH=src .venv/bin/python benchmarks/bench_pipeline_latency.py
```

Outputs land in `benchmarks/results/`.

## v1.1 benchmark roadmap

* AI4Privacy PII-Masking-300k full eval against the layered pipeline (requires `datasets` dep + ~30 GB disk for the corpus).
* arxiv 2410.23657 GitHub Issues Secrets Benchmark per-secret-type F1.
* OPF calibration sweep across confidence thresholds, comparison to Tonic.
* LLM judge re-run after prompt-template iteration and tuned-model work.
* Cross-category-overlap-aware corpus annotation (every valid span per example) so domain / email F1 numbers reflect detector behavior rather than annotation gaps.
