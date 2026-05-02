# DEC-019: Per-rule audit_only schema; LLM judge shipped but not validated at v1

**Date:** 2026-05-06
**Status:** LLM judge half superseded by [DEC-025](025-llm-judge-removal-after-v1.1-validation.md) (validation completed at v1.1, component removed). Per-rule `audit_only` schema remains in force.
**Phase:** v1 (benchmarks + shipping prep)
**Author:** MahdiHedhli

---

## Context

Two adjacent decisions logged together because they were resolved in
the same v1 morning window:

1. The v1 daily report flagged that `audit_only` was a top-level
   policy field but the brief described per-rule semantics. the v1 plan
   approved the schema extension. Operator workflow is "audit-only this
   one rule for two weeks then promote," which requires per-rule
   granularity.
2. The v1 daily report flagged that the LLM judge was implementation-
   verified (11 mocked unit tests) but not detection-verified (no real
   Ollama call producing a finding). The the v1 plan mandated a
   morning diagnostic before benchmarks: judge must produce >=1
   detection on obvious paraphrased PII, and pipeline latency must be
   measurably higher with judge enabled vs disabled. Failure to meet
   either is a hard stop with a documented blocker.

## Per-rule audit_only

### Decision

`PolicyRule.audit_only: bool | None = None`. Resolution order:

1. If the matching rule has `audit_only` explicitly set to `True` or
   `False`, use it.
2. Otherwise inherit `Policy.audit_only` (default `False`).

Backward compat: a policy without per-rule overrides behaves
identically to the v1 implementation. A policy with
`audit_only: true` at the top level applies to all rules unless a
rule explicitly sets `audit_only: false`.

### Implementation

`Policy.is_rule_audit_only(category, confidence)` resolves the flag.
The action engine's main loop now sorts each detection into one of
six buckets (`{block, mask, tokenize} x {enforce, audit}`). Audit-only
detections emit audit events but do NOT apply their action. Enforce
detections apply normally. Audit and enforce can mix on a single
request: a `BLOCK`-enforce on a credential will block the request,
and an `audit_only` rule on emails will still emit its events for
the same request so operators see what fired.

6 unit tests in `tests/unit/test_per_rule_audit_only.py`: backward
compat (policy-level audit-only with no rule overrides), rule-level
True overriding policy-level False, rule-level False overriding
policy-level True, mixed audit+enforce on a single request, the
`Policy.is_rule_audit_only` resolution helper.

### Consequences

- Operators can promote rules incrementally: ship a new rule as
  audit-only, watch the audit log for two weeks, flip to enforce.
- Audit log can carry events even on requests that block, so the
  operator review of "what does this policy catch" is complete.
- The `audit` field on `EngineResult` now mixes enforce-action audit
  entries (the existing per-detection audit trail) and audit-only
  entries (the would-have rows). Callers reading the field see all
  detections that fired regardless of enforcement.

## LLM judge: shipped but not validated at v1

### Diagnostic results

Ran the v1-mandated diagnostic at `local/scratch/llm_judge_diagnostic.py`.
Wiring is verified; detection is not.

**Setup:** Native Ollama on macOS (Metal GPU acceleration). Tested two
models: `qwen2.5:1.5b-instruct-q4_K_M` (~1 GB) and the v1 default
`llama3.2:3b-instruct-q4_K_M` (~2 GB). Default prompt template from
`src/promptguard/detectors/llm_judge.py`.

**Wiring (Check 2: latency delta):** PASS. Pipeline-with-judge is
measurably slower than pipeline-without-judge:

  - 1.5B model:  judge call adds ~150ms per request.
  - 3B model:    judge call adds ~1700ms per request.

The judge is being invoked end-to-end through the pipeline. The
`async_post_call_streaming_iterator_hook` wiring works.

**Detection (Check 1: single-prompt):** FAIL. Three diagnostic prompts
(paraphrased database credential, paraphrased API key reference, PII
via natural-language phone number) yielded zero detections from both
models. Inspecting raw model output:

  - `qwen2.5:1.5b`: returns the literal string `\`\`\`json\n[]\n\`\`\``
    for every prompt, including prompts with explicit Sarah-Mitchell-style
    PII. The model is following the "return JSON" instruction but
    interpreting "PII" too narrowly.
  - `llama3.2:3b`: emits text that looks JSON-shaped but is malformed:
    `["category": "email", "start": 34, "end": 41], ["category": "name", ...]`.
    Square brackets around key:value pairs is invalid JSON; the parser
    correctly drops it. Even when manually fixed, the spans are
    fabricated and don't match the input text.

**Verdict:** the default prompt template + small (1.5-3B) local Ollama
models do not produce reliably-shaped, content-correct findings.
Larger models (8B+) might work, but the v1 design point ("small,
fast, local LLM as a backstop") rules them out. Improving the prompt
template is possible (few-shot examples, stricter format requirement)
but not within the v1 timebox.

### Decision

Ship the LLM judge **shipped but not validated** at v1. Concrete:

- Adapter code stays as v1 wired it. Default-off in policy.
- `docs/llm-judge.md` already documents enable/disable, recommended
  models, and tolerance posture (zero findings on parse failure +
  warning log).
- An operator who turns on `detectors.llm_judge.enabled: true` with
  the default model gets working wiring, real Ollama calls, and zero
  detections on the test prompts above. They will see no false
  positives (the model produces nothing the parser accepts) and they
  will catch nothing the regex/OPF/Presidio stages missed.
- v1 benchmarks run with judge disabled. The benchmark matrix loses
  the layered+judge column; we cite the diagnostic instead.
- v1.1 work item: prompt-template iteration with few-shot examples
  and a smaller-but-tuned model (e.g. fine-tuned llama3.2:3B for the
  PII task), or graduate to an 8B+ model with a documented latency
  cost.

### Consequences

- Operators reading `docs/llm-judge.md` get a clear v1 status: shipped,
  not validated. The doc gets a section noting this explicitly.
- Sprint summary lists this as the headline open issue going into v1.1.
- The 11 unit tests still pass: they verify the adapter's wiring, error
  handling, and parsing tolerance, not detection quality. Those guarantees
  hold; what's missing is the model+prompt quality assurance.

### Revisit if

- A v1.1 contributor lands a tuned prompt template that produces
  parseable JSON from a 3B-class model.
- A small fine-tune for the PII task ships as a community Ollama model.
- We accept the latency hit of an 8B+ model and bump the default
  recommendation.

## Implementation notes

- `local/scratch/llm_judge_diagnostic.py` runs the diagnostic. The
  log files at `local/scratch/llm_judge_diagnostic_*.log` are the
  evidence trail.
- Native Ollama on macOS is dramatically faster than docker-Ollama
  on Apple Silicon (61 tok/s native vs 0.28 tok/s in container, 220x
  factor). This is a deployment note worth surfacing in v1.1
  packaging documentation.
- `docs/llm-judge.md` should be updated with the "shipped but not
  validated at v1" status; deferring the doc-edit to the v1
  benchmarks docs work since both touch operator-facing material.
