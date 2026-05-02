# PromptGuard — Research Notes & Decision Log

**Project:** PromptGuard
**Repo:** `github.com/MahdiHedhli/PromptGuard`
**Owner:** Mahdi Hedhli / 42 Holdings
**Started:** 2026-04-30
**Output:** Open source repo + blog post
**Target ship:** 14 calendar days from kickoff
**Reference baseline:** Rama (Muh. Fani Akbar), *Masking PII Or Sensitive Data Before Sending to AI Using LiteLLM*, 2026-04-24, https://labs.secengai.com/p/masking-pii-or-sensitive-data-before-sending-to-ai-using-litellm

---

## 1. Project Goals

1. Build an MVP that prevents sensitive data from leaving user machines via LLM/AI tool usage.
2. Deploy-in-minutes UX: clone repo, `docker compose up`, working with sensible defaults.
3. Ship architecture (adapter framework) with reference stubs that demonstrate enterprise-DLP integration shape.
4. Produce a publishable blog post that builds on Rama's work, not duplicates it.

## 2. Differentiation from Rama's Post

Rama's post is a strong practitioner tutorial: stand up LiteLLM, turn on built-in patterns, done. PromptGuard's blog goes a layer up — the architectural and policy-integration discussion that a CISO would actually use to make a deployment decision. Scope:

- Multi-stage detection: regex + OpenAI Privacy Filter + Presidio custom recognizers + opt-in LLM judge.
- Reversible TOKENIZE with bidirectional rewriting, including streaming.
- Adapter framework: where do rules come from, how are they distributed and attested?
- DLP integration shape (Purview, ICAP) as PoC stubs.
- Centralized vs local architecture: addressed analytically in v1, real impl + benchmark in v1.1.
- Mobile-user angle in the centralized-proxy discussion.

## 3. Threat Model

### Adversaries / risk vectors
- Inadvertent disclosure: developer pastes credentials, internal IPs, customer data into prompts.
- NDA / contractual violation: client data flows to a third-party LLM provider not covered by NDA.
- Regulatory exposure: PHI, PCI, ITAR, GDPR-protected data sent to a non-compliant processor.
- Compromised LLM provider: data retention, breach, or subpoena exposes prompt content.
- Policy drift: developer disables or misconfigures local protection.
- **Token-map ledger as attack surface (NEW):** TOKENIZE creates a persistent local mapping of original-to-token values. The ledger itself is sensitive datastore, subject to subpoena, may violate retention requirements in some compliance regimes. MASK is the answer when the ledger itself is the threat.

### In scope (v1)
- Text payloads to commercial LLM APIs (Anthropic + OpenAI-compatible).
- Tool-using clients that respect `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` env vars (Claude Code, Cursor, Continue.dev, custom agents).
- Streaming response handling (TOKENIZE round-trip on streamed output).

### Out of scope (v1, in scope later)
- Image / file uploads to LLMs (v1.x).
- Browser-based ChatGPT / Claude.ai (v1.1/v2 browser extension).
- On-device LLMs (no exfiltration risk).

### Out of scope (philosophical)
- LLM provider behavior post-receipt.
- Adversarial-developer threat model (cooperative-but-fallible users assumed).
- Cross-document prompt-injection-driven exfiltration (separate problem).

## 4. Architectural Decisions (LOCKED)

| # | Decision | Resolution |
|---|---|---|
| 1 | Interception layer | Local proxy with central policy sync |
| 2 | Detection engine | Multi-stage: Regex + OPF + Presidio custom + opt-in LLM judge |
| 3 | DLP integration | Adapter framework with reference + PoC stubs (Purview, ICAP); sample import files for testing |
| 4 | Tooling scope (v1) | Anthropic + OpenAI-compatible APIs; browser extension in v1.1/v2 |
| 5 | Reversible masking | Per-pattern: BLOCK / MASK / TOKENIZE configurable |
| 6 | LLM-judge default | Built-in (architecturally), shipped OFF in v1; tuning + benchmarks in v1.1 |
| 7 | Repo + naming | `github.com/MahdiHedhli/PromptGuard` |
| 8 | Centralized proxy mode | Discuss in v1 blog (incl. mobile angle); real impl deferred to v1.1 |
| 9 | Browser extension | v1.1/v2 |
| 10 | Streaming TOKENIZE | Locked into v1 with documented buffering strategy; hardening in v1.1 |
| 11 | OPF integration | Ship as default DetectorAdapter alongside Presidio in v1 |

## 5. Action Semantics

| Action | Behavior | Reversible? | Trade-off |
|---|---|---|---|
| BLOCK | Reject request, return error to calling tool with violation detail | N/A | Strict; breaks workflow |
| MASK | Replace with static tag (e.g. `[EMAIL_REDACTED]`). LLM sees tag; user sees tag in responses | No | No token-map ledger to leak; LLM responses lose specificity |
| TOKENIZE | Replace with unique token (e.g. `[EMAIL_001]`) mapped per-conversation. LLM sees token; user sees original restored in responses | Yes | Workflow continuity; token-map ledger is sensitive datastore |

### Default policy mapping (CONFIRMED)

```yaml
private_key:    BLOCK      # never round-trip a key
cloud_api_key:  BLOCK
database_url:   BLOCK
jwt:            BLOCK      # configurable: TOKENIZE if LLM needs to reason about JWT structure
email:          MASK       # configurable: TOKENIZE for email workflow automation
domain:         TOKENIZE   # round-trip needed for analysis context
internal_ip:    TOKENIZE
customer_name:  TOKENIZE
```

## 6. Detector Architecture

```
DetectionPipeline (multi-stage, configurable layering)
├── RegexDetector              # stage 1: structured/deterministic (keys, JWTs, IPs, DB URLs)
├── OPFDetector                # stage 2: context-aware PII (names, emails, addresses, phones, free-form secrets)
│                              #          OpenAI Privacy Filter (Apache 2.0, released 2026-04-22)
├── PresidioDetector           # stage 3: org-specific custom recognizers (codenames, customer names)
```

### Why multi-stage instead of single detector
- Regex catches structured data deterministically; never misses a known pattern.
- OPF catches context-aware PII a regex would miss (paraphrased, contextual).
- Presidio custom recognizers catch org-specific entities OPF wasn't trained on.
- LLM judge catches paraphrased secrets and adversarial reformulations.
- Any layer flagging is sufficient to trigger the configured action.

### OPF integration notes
- Released 2026-04-22 by OpenAI under Apache 2.0
- 1.5B params, 50M active (MoE); CPU mode supported
- 8 categories: account_number, private_address, private_email, private_name, private_phone, secret, private_date, background
- Default operating point is precision-tuned; recall calibration knob via Viterbi decoding
- Tonic.ai benchmark (2026-04-24) showed default recall is poor on out-of-distribution data (web crawl 10%, EHR 38%) — reinforces the layering decision
- Map our policy categories onto OPF outputs:
  - email → private_email
  - customer_name → private_name (with caveats)
  - jwt / cloud_api_key / private_key → secret (regex layer is primary; OPF as backup)
  - account_number → BLOCK or TOKENIZE (configurable)
- HuggingFace integration via `transformers.pipeline(task="token-classification", model="openai/privacy-filter")`

## 7. Policy Source Architecture

```
PolicyAdapter interface
├── LocalYAMLPolicy            # reference, default
├── GitManifestPolicy          # signed manifest pull (central policy distribution)
├── PurviewDLPPolicy           # PoC stub; sample SIT export file for import testing
└── ICAPPolicy                 # PoC stub; sample ICAP request fixtures for testing
```

## 8. Test Corpora

| Corpus | Source | Use | License |
|---|---|---|---|
| AI4Privacy PII-Masking-300k | HuggingFace `ai4privacy/pii-masking-300k` | PII detection benchmarking (eval only, NOT training) | "other" — academic OK with citation; commercial training requires licensing |
| GitHub Issues Secrets Benchmark | arxiv 2410.23657 (Nov 2025) | Secrets detection benchmarking; 54,148 instances, 5,881 verified secrets | Check at integration time |
| Synthetic supplement | Generated by us | Org-specific entities (codenames, customer names, internal hostnames) | Project-owned |

License caveat documented in README and blog post.

## 9. Compressed Roadmap (10 working days, 14 calendar)

| Day | Focus |
|---|---|
| 1 | Repo scaffold, threat model md, Docker compose (LiteLLM proxy + Presidio + OPF), baseline pattern set |
| 2 | Action engine: BLOCK/MASK/TOKENIZE primitives, config schema, error responses |
| 3-4 | Reversible TOKENIZE with streaming buffering strategy; per-conversation token map; request rewrite + response restore |
| 5 | Per-pattern policy config; sample policies (default, NDA-strict, healthcare-leaning) |
| 6-7 | Adapter framework: detector + policy-source interfaces; ship Regex + OPF + Presidio as detectors; LocalYAML + GitManifest as policy sources; Purview + ICAP as PoC stubs with sample import files |
| 8 | LLM judge plug-point via Ollama, off by default, hook documented |
| 9 | Benchmarks: FP/FN against AI4Privacy + GitHub-Issues-Secrets + synthetic; p50/95/99 latency overhead |
| 10 | Packaging polish (one-line install, README), blog post draft |

3-4 day buffer baked in for unknowns.

## 10. Open Questions (current)

1. **Streaming buffer size N.** Default to 256 chars? Tradeoff between tail latency and token-mapping precision. Empirical tune during v1.
2. **OPF model storage.** ~3GB on first run. Ship Docker image with model baked in (large image, fast first run) or download on first start (small image, slow first run)? Probably download-on-start with a clear progress indicator.
3. **Source code blocks.** High-density secret real estate. Treat differently or rely on standard detectors? My instinct: same detectors but heightened sensitivity threshold inside fenced code blocks.
4. **False-positive UX.** When proxy masks something the user didn't intend, what's the developer experience? Inline notification, audit log, override mechanism. v1 ships audit log + visible inline notification; override deferred to v1.1.
5. **Reversibility and prompt-injection risk.** A malicious LLM response trying to manipulate token-restoration logic. Mitigation: tokens use unguessable random IDs (not sequential), restoration is purely string-substitution from the map (no LLM-controlled lookups).

## 11. Deferred to v1.1

- Centralized proxy mode + multi-tenant gateway.
- Real Purview integration (Graph API auth, SIT pull, classifier translation).
- Real ICAP integration (Symantec/Forcepoint/Trellix testing).
- LLM judge tuning + FP/FN benchmarks.
- Browser extension (Chrome MV3 + Firefox).
- Centralized vs local perf benchmark with real numbers.
- Code-block-aware detection threshold.
- Streaming TOKENIZE edge case hardening.
- Override mechanism for false positives.
- Mobile centralized-proxy story (architectural sketch in v1 blog, real impl in v1.1).

## 12. Research Log

**2026-04-30** — Project kickoff. Reviewed Rama's LiteLLM post. Drafted threat model, solution space survey, initial roadmap (6 weeks). Decisions 1-3 locked.

**2026-04-30** (cont.) — Mahdi locked decisions 4-7. Compressed timeline to 14 calendar days. Centralized proxy + real Purview/ICAP deferred to v1.1. Repo named PromptGuard at github.com/MahdiHedhli/PromptGuard. Action semantics defined as BLOCK / MASK / TOKENIZE with distinct reversibility. Per-pattern policy config matches Mahdi's defaults.

**2026-04-30** (cont.) — Web research turned up: (a) AI4Privacy PII-Masking-300k as PII benchmark corpus, (b) arxiv 2410.23657 GitHub Issues Secrets Benchmark for secrets corpus, (c) **OpenAI Privacy Filter (OPF) released 2026-04-22 under Apache 2.0** — context-aware PII detector, 1.5B params, runs locally, state-of-the-art on PII-Masking-300k. Tonic.ai head-to-head benchmark (2026-04-24) showed default OPF recall is poor on out-of-distribution data, reinforcing layered-detection decision. Architecture revised to multi-stage: Regex + OPF + Presidio custom + opt-in LLM judge. OPF integrated as default DetectorAdapter alongside Presidio. Streaming TOKENIZE locked into v1. MASK clarification (token-map ledger as attack surface) added to threat model.

## 13. References & Related Work

- Rama, *Masking PII Or Sensitive Data Before Sending to AI Using LiteLLM*: https://labs.secengai.com/p/masking-pii-or-sensitive-data-before-sending-to-ai-using-litellm
- LiteLLM Content Filter docs: https://docs.litellm.ai/
- Microsoft Presidio: https://microsoft.github.io/presidio/
- **OpenAI Privacy Filter announcement**: https://openai.com/index/introducing-openai-privacy-filter/
- **OpenAI Privacy Filter repo**: https://github.com/openai/privacy-filter
- **OpenAI Privacy Filter HuggingFace**: https://huggingface.co/openai/privacy-filter
- **Tonic.ai OPF benchmark**: https://www.tonic.ai/blog/benchmarking-openai-privacy-filter-pii-detection
- **AI4Privacy PII-Masking-300k**: https://huggingface.co/datasets/ai4privacy/pii-masking-300k
- **GitHub Issues Secrets Benchmark (arxiv 2410.23657)**: https://arxiv.org/html/2410.23657
- Microsoft Purview Information Protection / Graph API: https://learn.microsoft.com/en-us/graph/api/resources/security-api-overview
- ICAP RFC 3507: https://www.rfc-editor.org/rfc/rfc3507
- Ollama (for local LLM judge): https://ollama.com/

## 14. Blog Post Outline (DRAFT)

1. Hook: NDA problem, reframed as a DLP gap rather than a regex challenge.
2. Why Rama's pattern approach is the right v0 and the wrong v1.
3. Threat model: what we're actually defending against, the token-map-as-ledger problem, non-goals.
4. Three architectural axes: interception point, detection engine, policy source.
5. Why local proxy + central policy sync; what centralized-only architecture costs analytically; mobile-user implications.
6. Multi-stage detection: regex + OPF + Presidio custom + LLM judge. Why layering, with FP/FN data.
7. Spotlight: OpenAI Privacy Filter — what dropped while we were building this, where it shines, where Tonic's data shows it doesn't.
8. Three actions, three semantics: BLOCK, MASK, TOKENIZE; the round-trip problem; the ledger problem.
9. Adapter framework: how PromptGuard plugs into Purview, ICAP, or whatever DLP stack the org already paid for. Sample import files included for PoC.
10. The LLM judge: why it's there, why it's off, when to turn it on.
11. Repo, deployment in 5 minutes, what's next in v1.1.
