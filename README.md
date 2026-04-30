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
docker compose up -d
```

Point your tools at the local proxy:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export OPENAI_BASE_URL=http://localhost:4000/v1
```

The default policy lives at `policies/default.yaml`. Sample policies for NDA-strict and healthcare-leaning configurations are in the same directory.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full picture and [docs/threat-model.md](docs/threat-model.md) for what PromptGuard does and does not defend against. The locked design decisions live in [docs/research-notes.md](docs/research-notes.md).

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run pytest
```

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Test corpora caveat

The PII detection benchmarks reference [AI4Privacy PII-Masking-300k](https://huggingface.co/datasets/ai4privacy/pii-masking-300k), which is licensed for academic evaluation only. Commercial training requires separate licensing. PromptGuard uses this corpus for evaluation, not training.
