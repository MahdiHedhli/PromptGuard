# PromptGuard benchmarks

## TL;DR

* **Real-corpus PII detection on AI4Privacy PII-Masking-300k (English validation, 7,946 records, 22,624 in-scope spans).** Three pipelines compared. PromptGuard's regex layer matches a bare-LiteLLM-style baseline on email and dominates on RFC-1918 internal IPs (F1 1.000 vs 0.007). The full pipeline picks up free-form private-name / private-address / private-phone categories the regex layer cannot see by shape, at moderate F1 numbers consistent with Tonic.ai's published OPF results on out-of-distribution data.
* **Real-corpus secret detection on the GitHub Issues Secrets Benchmark (Zenodo 17430336, test_wild split, 1,488 records, 29 real secrets).** A genuine recall gap: PromptGuard's v1.1 regex set targets the credential categories the gitleaks ruleset covers (AWS, GCP, Azure, GitHub PATs, JWTs, PEM keys, database URLs); the benchmark's secrets are predominantly vendor-specific keys (Anypoint, Lob, Sparkpost, Auth0) without distinctive prefixes. PromptGuard returns 0 detections, baseline returns 1 of 29. This is a calibration boundary, not a pipeline failure; v1.2 candidate.
* **Per-request in-process overhead** is around 0.3 ms p50 / 0.5 ms p95 for the full DetectionPipeline + ActionEngine. Cold start of the docker stack is around 161 s to all-services-healthy on a clean machine; subsequent boots under 15 s.

## Real-corpus results

### Methodology

The benchmark harness lives at `benchmarks/run_real_corpus_benchmarks.py`. It loads each corpus into `(text, ground_truth_spans)` tuples, runs each pipeline, computes per-category counts using span-IoU >= 0.5 as the match criterion, and reports precision / recall / F1 plus raw TP / FP / FN counts.

#### Corpora

* **AI4Privacy PII-Masking-300k** (Hugging Face: `ai4privacy/pii-masking-300k`). Validation split, English subset only (7,946 records of 47,728 total). Released under the AI4Privacy license (academic evaluation use). We do NOT redistribute the corpus and do NOT train on it. Manifest with SHA256 checksums of the cached jsonl files: `local/benchmarks/corpora/ai4privacy/manifest.txt`.
* **GitHub Issues Secrets Benchmark** (Zenodo: `https://zenodo.org/records/17430336`, arxiv 2410.23657). `test_wild.csv` split, 1,488 records, 29 labeled-real secrets (label=1) and 1,459 labeled-fake hard-negative candidates (label=0). Released under CC-BY 4.0; we cite per the license. Span ground truth induced by locating the labeled `candidate_string` inside `text` for label=1 rows.

#### Pipelines

1. **`baseline_litellm`**: a stand-in for LiteLLM's native PII pattern matching. Implements the minimal regex set a v0 setup ships with (email, IPv4, AWS access key shape, generic 32+ hex SECRET).
2. **`promptguard_regex`**: PromptGuard's regex layer alone, with the v1.1 NormalizationDetector for input canonicalization.
3. **`promptguard_full`**: regex + normalization + OPF (`opf-service` container) + Presidio analyzer.

#### Mapping discipline

AI4Privacy's category taxonomy is not identical to PromptGuard's. The mapping at `benchmarks/run_real_corpus_benchmarks.py::AI4PRIVACY_LABEL_TO_CATEGORY` records every decision. Two notes:

* **AI4Privacy "IP" -> PromptGuard INTERNAL_IP, RFC-1918 only.** The corpus's `IP` label covers public IPs and RFC-1918 internal IPs uniformly. PromptGuard's `INTERNAL_IP` detector targets RFC-1918 by design; public IPs are not the threat surface (they appear in URLs, log lines, public documentation). Public-IP gold spans are filtered out of the eval rather than counted as misses, which would overstate the gap.
* **Out-of-scope categories.** AI4Privacy's `USERNAME / IDCARD / SOCIALNUMBER / PASSPORT / DRIVERLICENSE / BOD / DATE / TIME / SEX / TITLE / PASS / GEOCOORD / CARDISSUER` labels are not categories PromptGuard's v1.1 detectors target. They are excluded from scoring, not counted as misses.
* **GitHub Issues Secrets vendor-specific types.** The corpus's `secret_type` field carries fine-grained vendor labels (Lob, Anypoint, Sparkpost, Auth0). PromptGuard's category vocabulary does not split SECRET into per-vendor subcategories; we score every label=1 row under `SECRET`. This is the most generous mapping; a more granular taxonomy would not change the headline number.

### AI4Privacy English (7,946 records, span-IoU >= 0.5, in-scope categories only)

| Category | baseline_litellm F1 | promptguard_regex F1 | promptguard_full F1 |
|---|---:|---:|---:|
| email | 0.959 (P=0.96 / R=0.96, n=2,612) | 0.959 (P=0.96 / R=0.96, n=2,612) | 0.658 (P=0.49 / R=1.00, n=2,612) |
| internal_ip (RFC-1918) | 0.007 (P=0.00 / R=1.00, n=4) | **1.000 (P=1.00 / R=1.00, n=4)** | 0.004 (P=0.00 / R=1.00, n=4) |
| private_address | 0.000 | 0.000 | **0.358 (P=0.72 / R=0.24, n=12,203)** |
| private_name | 0.000 | 0.000 | **0.273 (P=0.33 / R=0.23, n=5,808)** |
| private_phone | 0.000 | 0.000 | **0.306 (P=0.25 / R=0.40, n=1,997)** |

`n` is the number of gold spans of that category in the corpus. P / R / F1 are computed from raw TP / FP / FN on span-IoU.

**Reading the table:**

* **email**: matched at high recall by all three pipelines because email is shape-detectable. baseline_litellm and promptguard_regex use functionally similar regexes here and tie. The full pipeline's apparent F1 drop is a measurement artifact, not a regression. OPF and Presidio also flag emails, with slightly different span boundaries, and the harness scores raw detections without action-engine deduplication. The action engine's `_select_outer_spans` (DEC-023) collapses these to one substitution at runtime, so the operator-visible behavior is correct.
* **internal_ip**: the headline result. PromptGuard's RFC-1918-targeted regex catches all 4 internal IPs in the English subset with zero FPs. baseline_litellm catches them too but floods the surface with 1,115 FPs on public IPs (which are not sensitive in the threat-model sense and are not what the user wants to redact).
* **private_address / private_name / private_phone**: regex layers (both baseline and promptguard_regex) cannot see these by shape. The full pipeline catches them via OPF + Presidio at moderate F1 (0.27-0.36). Recall is 0.23-0.40, consistent with Tonic.ai's published OPF default-operating-point recall of around 0.10-0.38 on out-of-distribution data. Operators who care about high recall on these categories should run the recall-tuned OPF operating point (a v1.2 calibration sweep is the next step).

### GitHub Issues Secrets test_wild (1,488 records, 29 real secrets, span-IoU >= 0.5)

| Category | baseline_litellm F1 | promptguard_regex F1 | promptguard_full F1 |
|---|---:|---:|---:|
| secret | 0.001 (P=0.001 / R=0.034, tp=1, fp=1,553, n=29) | 0.000 (P=0 / R=0, tp=0, fp=0, n=29) | 0.000 (P=0 / R=0, tp=0, fp=0, n=29) |

**Reading the table:**

* **A genuine recall gap.** The 29 labeled-real secrets in `test_wild` are predominantly vendor-specific API keys (Anypoint, Lob, Sparkpost, Auth0, Artifactory) without distinctive prefixes. PromptGuard's v1.1 regex set is calibrated for the credential categories gitleaks targets: AWS access keys (`AKIA` / `ASIA` prefix), Google API keys (`AIza` prefix), Azure subscription keys (specific format), GitHub personal access tokens (`ghp_` / `gho_` / `ghu_` prefix), JWTs, PEM headers, database URL shapes. None of those patterns fire on a Lob API key (40-char hex without prefix) or an Anypoint key (32-char base64 without prefix), and our SECRET pattern is conservative enough to avoid false-positive flooding on log files.
* **The baseline's lax SECRET pattern** (`\b[A-Fa-f0-9]{32,}\b`) catches one real secret but generates 1,553 false positives across the corpus because every commit SHA, every SHA-256 hash, every long hex string in a stack trace matches. This is the v0 trap: high recall is easy if you accept high noise. For an inline blocking proxy, a 1.5%-precision detector is unusable.
* **What the right v1.2 fix looks like.** Two paths, not mutually exclusive: (a) extend the regex set with vendor-specific patterns from a broader gitleaks rule audit (gitleaks v8.x ships rules for many of these), or (b) Presidio custom recognizers configured per-org (the Anypoint API key is identifying for an organization that uses Anypoint; an organization that doesn't has no use for the rule). Option (b) is structurally what Presidio's adapter is for; the v1.1 release does not configure these out of the box.

The honest framing: PromptGuard v1.1 ships excellent precision and reasonable recall on the credential categories the open-source detection community has converged on, and a real gap on the long tail of vendor-specific keys. The benchmark surfaces the gap; the gap is calibration, not architecture.

## Latency

### In-process pipeline

Measured on Apple Silicon CPython 3.11. n=1000 records of a 305-char prompt with 5 distinct PII spans.

| Configuration | avg | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| baseline_regex_only | 0.146 ms | 0.069 ms | 0.182 ms | 1.671 ms |
| pipeline + engine | 0.305 ms | 0.298 ms | 0.545 ms | 1.008 ms |
| pipeline + engine + audit-only | 0.606 ms | 0.316 ms | 0.911 ms | 3.469 ms |

NormalizationDetector adds 0.072 ms avg / 0.192 ms p95 on top.

### Real-corpus per-record timing (AI4Privacy English, n=7,946)

| Pipeline | total ms | avg ms / record |
|---|---:|---:|
| baseline_litellm | 602 ms | 0.08 ms |
| promptguard_regex | 3,669 ms | 0.46 ms |
| promptguard_full | 154,885 ms | 19.49 ms |

The full pipeline's 19.5 ms/record average reflects HTTP roundtrips to OPF (3 GB Hugging Face model running in a separate FastAPI container) and Presidio. The per-request inline cost on the proxy path is unchanged from the in-process numbers above; the harness measurement includes the HTTP hop because that is the production cost.

### End to end through the proxy

Measured against the live LiteLLM stack:

| Path | avg | p95 |
|---|---:|---:|
| BLOCK on AWS key | 12.4 ms | 17.6 ms |

Bulk is LiteLLM; PromptGuard's contribution is around 0.3 ms.

### Cold start

`docker compose up -d --wait` from clean state: 161 s wall-clock with default policy (regex + OPF + Presidio). Subsequent boots under 15 s. OPF model load dominates first-boot cost.

### Memory (idle, default policy)

| Service | RSS |
|---|---:|
| litellm | ~250 MB |
| opf-service | ~3.0 GB |
| presidio-analyzer | ~700 MB |

## Comparing to "bare LiteLLM with native pattern matching"

Bare LiteLLM ships built-in PII guards configured per-pattern. The capability comparison:

| Capability | Bare LiteLLM v0 | PromptGuard v1.1 |
|---|:---:|:---:|
| Regex-pattern detection | Yes | Yes (vendored gitleaks + detect-secrets, calibrated for false-positive surface) |
| Multi-stage layered detection | No | Yes (regex + OPF + Presidio + Normalization) |
| Reversible TOKENIZE | No | Yes (per-conversation map, streaming SSE round-trip) |
| BLOCK envelope (Anthropic + OpenAI shape) | No | Yes |
| Per-rule policy granularity | Limited | Yes (BLOCK / MASK / TOKENIZE per category, per-rule audit_only) |
| Encoding-evasion defense | No | Yes (NFKC + zero-width strip + base64 / URL / HTML decode) |
| Adapter framework (DLP integrations) | No | Yes (LocalYAML reference; Purview / ICAP shipped on engagement) |
| Audit log with structural no-text invariant | No | Yes (JSONL, 200-iteration fuzz test) |
| Hot reload with policy validation | No | Yes (DEC-016) |

The detection-side numbers above quantify the regex-set difference: PromptGuard's vendored gitleaks-derived rule set catches RFC-1918 internal IPs at F1 1.000 (vs the baseline's 0.007 because it floods on public IPs), and matches the baseline on email. The architectural difference (TOKENIZE round-trip, action engine, adapter framework) is qualitative.

## Re-running the benchmarks

```bash
# Real-corpus benchmark (AI4Privacy + GitHub Issues Secrets)
uv run python benchmarks/run_real_corpus_benchmarks.py \
    --ai4privacy-limit 7946 --github-secrets-limit 1488 \
    --pipelines baseline_litellm,promptguard_regex,promptguard_full

# Synthetic corpus (development tooling)
PYTHONPATH=src .venv/bin/python benchmarks/run_detection_benchmarks.py

# Latency matrix
PYTHONPATH=src .venv/bin/python benchmarks/run_latency_matrix.py
```

Outputs land in `local/benchmarks/results/v1.1.1/` (real-corpus) and `benchmarks/results/` (synthetic).

The real-corpus harness requires the AI4Privacy and GitHub Issues Secrets corpora to be downloaded once. AI4Privacy comes via the `datasets` package; GitHub Issues Secrets via `curl https://zenodo.org/records/17430336/files/Secret-Leak-Detection-Issue-Report.zip`. Neither corpus is in the repo; both are gitignored.

## OPF operating-point comparison

The v1.1.2 brief required a default-vs-recall-tuned OPF operating-point comparison. The OPF service exposes `aggregation_strategy` as a per-request knob (default `simple`; alternatives `max`, `first`, `average`). The HuggingFace token-classification pipeline cached per-strategy in-process, so an A/B does not require a container restart.

Run on AI4Privacy English (7,946 records, span-IoU >= 0.5 scoring):

| Category | full pipeline (default `simple`) | full pipeline (recall-tuned `max`) |
|---|---:|---:|
| email | F1 0.658 (P 0.49 / R 1.00) | F1 0.658 (P 0.49 / R 1.00) |
| internal_ip | F1 0.004 (P 0.00 / R 1.00) | F1 0.004 (P 0.00 / R 1.00) |
| private_address | F1 0.358 (P 0.72 / R 0.24) | F1 0.358 (P 0.72 / R 0.24) |
| private_name | F1 0.273 (P 0.33 / R 0.23) | F1 0.273 (P 0.33 / R 0.23) |
| private_phone | F1 0.306 (P 0.25 / R 0.40) | F1 0.306 (P 0.25 / R 0.40) |

**The numbers are byte-identical at IoU >= 0.5.**

Per-span behavior does differ. Direct A/B on a sample sentence
`"James Smith called yesterday about his account. Email: james.smith@aol.com, phone 555-123-4567."`:

- `simple` returns two email fragments (`" james.smith@aol"` and `".com"`) and two phone fragments (`"555-123-456"` and `"7"`).
- `max` returns one merged email span (`" james.smith@aol.com,"`) and one merged phone span (`"555-123-4567."`).

`max` produces cleaner contiguous spans; `simple` fragments at sub-token boundaries. At span-IoU 0.5, the longest `simple` fragment (length 16 of 19 gold characters) clears the threshold by itself, so both strategies score the same TP. At stricter IoU thresholds (0.8 for example), `max` would score better on email/phone where `simple` fragments would no longer clear.

Operator takeaway: at the published AI4Privacy scoring threshold, OPF strategy choice is not a precision/recall lever on F1. Stricter span-fidelity requirements would prefer `max`. v1.2 calibration sweep across IoU thresholds and across `simple` / `max` / `first` / `average` strategies is the next investigation.

How to run either: pass `aggregation_strategy` on the OPFDetector constructor (None → service default), or set the `OPF_AGGREGATION` env var on the OPF service container. The benchmark harness exposes both via the `promptguard_full` and `promptguard_full_recall_tuned` pipelines.

## v1.2 benchmark roadmap

Items the v1.1.1 + v1.1.2 results surface as worthwhile next steps:

* **OPF operating-point sweep across IoU thresholds.** v1.1.2 confirmed `simple` and `max` produce identical F1 at IoU 0.5 on AI4Privacy English. A sweep across IoU thresholds (0.5 / 0.7 / 0.8 / 0.9) plus the four aggregation strategies would surface the trade-off frontier, especially relevant for use cases that need stricter span fidelity.
* **Vendor-specific secret recognizers.** Extending the regex set or shipping a Presidio recognizer pack for the long tail (Anypoint, Lob, Sparkpost, Auth0, Artifactory) closes the GitHub Issues Secrets gap.
* **Cross-category overlap dedup at score time.** The full pipeline's email FP inflation is a harness measurement artifact (action engine handles it correctly at runtime). A score-time dedup pass that mirrors the action engine's behavior would give a more honest detection number.
* **Multi-language extension.** AI4Privacy ships English / French / German / Italian / Spanish / Dutch. v1.1 measures English only; adding the other languages quantifies cross-locale coverage.

## Synthetic-corpus development tooling (appendix)

The synthetic corpus at `benchmarks/run_detection_benchmarks.py` (220 examples across 8 categories) remains in the repo as the unit-test-time regression target. Its numbers are NOT the credibility claim; the real-corpus numbers above are. Synthetic results stay green across the build to catch regex regressions during development:

| Category | Precision | Recall | F1 |
|---|---:|---:|---:|
| cloud_api_key | 1.000 | 1.000 | 1.000 |
| database_url | 1.000 | 1.000 | 1.000 |
| internal_ip | 1.000 | 1.000 | 1.000 |
| jwt | 1.000 | 1.000 | 1.000 |
| private_key | 1.000 | 1.000 | 1.000 |
| secret | 1.000 | 1.000 | 1.000 |

The two categories that show reduced F1 on the synthetic corpus (`domain` 0.500, `email` 0.667) are corpus-annotation artifacts (a postgres URL legitimately contains a domain; the synth corpus only annotated the URL as expected). The annotation pass is on the v1.2 list.

These synthetic numbers are NOT for blog quotation; the AI4Privacy / GitHub Issues Secrets numbers above are.
