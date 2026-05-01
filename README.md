# PromptGuard

Local LLM proxy that prevents PII and sensitive data from leaving developer machines.

**Status:** v1 in active development. Targeting first release within 14 days of kickoff (2026-04-30).

## What it does

PromptGuard sits between your AI tooling (Claude Code, Cursor, Continue.dev, custom agents) and the upstream LLM provider. Every prompt is inspected by a layered detection pipeline before it leaves the host:

1. **Regex** for structured secrets: PEM private keys, AWS / GCP / Azure credentials, database URLs, JWTs, RFC 1918 addresses.
2. **OpenAI Privacy Filter (OPF)** for context-aware PII: names, emails, phones, addresses, free-form secrets.
3. **Microsoft Presidio** with custom recognizers for org-specific entities: codenames, customer names, internal hostnames.
4. **Optional LLM judge** (off by default) for paraphrased and adversarial cases.

When a detector fires, a per-pattern policy decides what happens:

| Action   | Behavior                                                    | Reversible | Use when                                |
|----------|-------------------------------------------------------------|------------|-----------------------------------------|
| BLOCK    | Reject the request, return a violation error.               | n/a        | Credentials, PHI, anything contractual. |
| MASK     | Replace with a static tag (`[EMAIL_REDACTED]`).             | No         | Token-map ledger is itself a risk.      |
| TOKENIZE | Replace with unique per-conversation token, restore on out. | Yes        | Workflow continuity matters.            |

## Quick start

```bash
git clone https://github.com/MahdiHedhli/PromptGuard
cd PromptGuard

# Provide upstream API keys. ANTHROPIC_API_KEY enables claude-* models;
# OPENAI_API_KEY enables gpt-* models. .env is gitignored.
cp .env.example .env
$EDITOR .env

# Bring up the proxy. First boot downloads the OPF model (~3GB) from
# HuggingFace; expect ~3 minutes. Subsequent boots reuse the cached
# volume and complete in seconds.
docker compose up -d --wait
```

Point your tools at the local proxy:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export OPENAI_BASE_URL=http://localhost:4000/v1
```

The default policy lives at [`policies/default.yaml`](policies/default.yaml). Four other shipped policies cover common postures: [`nda-strict.yaml`](policies/nda-strict.yaml), [`healthcare-leaning.yaml`](policies/healthcare-leaning.yaml), [`pentest-engagement.yaml`](policies/pentest-engagement.yaml), and [`regex-only.yaml`](policies/regex-only.yaml). Switch policies with:

```bash
PROMPTGUARD_POLICY_FILE=/app/policies/nda-strict.yaml docker compose up -d
```

### Air-gapped or restricted-egress install

If the host cannot reach HuggingFace, run with the regex-only policy. OPF and Presidio are disabled; structured-secret coverage is unchanged but free-form PII coverage is reduced. See [`docs/policy-schema.md`](docs/policy-schema.md) for the trade-offs.

```bash
PROMPTGUARD_POLICY_FILE=/app/policies/regex-only.yaml docker compose up -d --wait
```

### Port collisions

If something on the host already binds port 4000 (LiteLLM), 5002 (Presidio), or 8081 (OPF), override with `PROMPTGUARD_LITELLM_PORT`, `PROMPTGUARD_PRESIDIO_PORT`, `PROMPTGUARD_OPF_PORT`. Set them in `.env` to make the override durable.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full picture and [docs/threat-model.md](docs/threat-model.md) for what PromptGuard does and does not defend against. The locked design decisions live in [docs/research-notes.md](docs/research-notes.md).

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run pytest
```

For end-to-end integration tests without consuming real Anthropic credits, bring up the included mock-Anthropic upstream:

```bash
PROMPTGUARD_LITELLM_CONFIG=./docker/litellm/config-mock.yaml \
    docker compose --profile mock up -d --wait
uv run pytest -m mock_upstream
```

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Benchmark methodology and corpora

The detection numbers in [docs/benchmarks.md](docs/benchmarks.md) come from a synthetic corpus of 220 examples generated locally by `benchmarks/run_detection_benchmarks.py`. We did NOT run [AI4Privacy PII-Masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k) against the pipeline in v1; the corpus and the `datasets` download path did not fit the v1 budget. Where AI4Privacy results are referenced, they are Tonic.ai's published OPF numbers on that corpus, cited as external sanity check rather than a result we reproduced.

AI4Privacy is licensed for academic evaluation only; commercial training requires separate licensing. The v1.1 benchmark roadmap in [docs/benchmarks.md](docs/benchmarks.md) tracks the planned full AI4Privacy run against the layered pipeline.
