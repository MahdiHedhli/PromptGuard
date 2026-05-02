# DEC-025: Remove LLMJudgeDetector after v1.1 validation

**Date:** 2026-05-02
**Status:** Accepted (supersedes DEC-018, DEC-019)
**Phase:** v1.1 phase 3 (LLM judge resolution)
**Author:** MahdiHedhli

---

## Context

DEC-019 left the LLM judge component in a "shipped but not validated"
state at v1: the wiring was correct (verified via latency delta), the
default prompt + small (1.5-3B) Ollama models produced malformed JSON
or zero detections, the failure modes returned zero detections rather
than corrupting the pipeline, and validation against a real benchmark
was deferred to v1.1.

The v1.1 sprint brief listed a strict resolution requirement: validate
the judge against a 50-prompt corpus or remove the component. Pass
criteria, all of which had to hold simultaneously:

- parse-success rate >= 95%
- false-positive rate on clean prose < 10%
- judge-enabled detection on the paraphrased-PII subset is a strict
  superset of the deterministic stages and adds >= 10% recall
- per-call latency p95 < 500 ms

If validation passed, the judge would ship as validated; if it failed
on any criterion, the component would be removed cleanly rather than
left half-shipped.

## What was tried

A validation harness was built at
`benchmarks/run_llm_judge_validation.py` (since removed). The corpus
split: 25 clean prompts (technical questions with no PII) and 25
paraphrased-PII prompts (real protected attributes expressed in
natural-language form, e.g. "her address is roughly two blocks from
the train station, brick house with green shutters", "his phone
number, area code is the one for downtown Boston").

Two sweeps were run.

**Sweep 1: existing default prompt + qwen2.5:7b-instruct-q4_K_M.**
Detection results were uniformly empty (`[]`) on the paraphrased
subset. The model interpreted the prompt's category enumeration as
exclusive and refused to flag spans whose category match was loose.

| Metric | Value | Threshold | Pass? |
|---|---:|---:|:---:|
| Parse-success rate | 100% | >= 95% | YES |
| FP rate (clean) | 0% | < 10% | YES |
| Recall lift on paraphrased | 0% | >= 10% | NO |
| Latency p95 | 626 ms | < 500 ms | NO |

**Sweep 2: tightened prompt with three few-shot examples and an
explicit "be liberal; false positives are acceptable; missing PII is
not" instruction + qwen2.5:7b-instruct-q4_K_M.** Detection capability
flipped:

| Metric | Value | Threshold | Pass? |
|---|---:|---:|:---:|
| Parse-success rate | 100% | >= 95% | YES |
| FP rate (clean) | 0% | < 10% | YES |
| Recall lift on paraphrased | 100% | >= 10% | YES |
| Latency p95 | 1555 ms | < 500 ms | NO |
| Latency p99 | 1811 ms | (info) | - |

(A third sweep with `qwen2.5:1.5b` + the same v2 prompt explored
whether a smaller model could close the latency gap. It returned
parse=100%, recall lift=100%, but FP rate climbed to 64% on clean
prose and p95 was still 780 ms, so two of the four gates regressed.)

## Decision

Remove `LLMJudgeDetector` from the codebase, the policy schema, the
sample policies, and the docs. Per the v1.1 brief: "If validation
fails after 1.5 days of effort: Remove LLMJudgeDetector from the
codebase entirely. Don't leave dead code."

The detection-side validation is unambiguous: the judge does what it
was designed to do, given a tightened prompt and a 7B-class model. The
latency-side validation is also unambiguous: the model is structurally
incapable of producing the required output inside the 500 ms p95
budget on the hardware that ships PromptGuard's reference deployment
(Apple Silicon, native Ollama, Metal acceleration, 7B q4_K_M
quantization). The brief's pass criteria are AND'd; one strict failure
fails the gate.

Removal preserves the project's "no dead code, no shipped-but-not-
validated components" rule (CLAUDE.md). It also closes the v1
ambiguity that drove the v1.1 work in the first place.

## Consequences

### Enables
- The v1.1 release ships with no "shipped but not validated"
  components. Every detector in the pipeline has a validation
  benchmark behind it.
- Reduced operational surface: operators no longer need to provision
  Ollama, pick a model, accept the latency hit, or worry about a
  misconfigured judge silently emitting nothing.
- The `DetectorAdapter` framework is unchanged. A future detector
  (a smaller distilled model, an external API-based judge, an
  async-only batch judge) plugs in via the same ABC.

### Constrains
- Paraphrased PII (the kind expressed in natural-language form
  rather than in shape-based form) is no longer caught at the
  detection layer. Operators who care about this class of leak
  rely on either Presidio's custom recognizers or on operator
  training. v1.2 candidate: an async / batch / offline judge
  mode that does not run on the per-request path.

### Revisit if
- Smaller distilled PII-classification models become available that
  fit the 500 ms budget at acceptable recall. The validation harness
  shape (50 prompts split clean / paraphrased, four-criteria gate)
  is the right re-test contract.
- Hardware accelerators in the typical developer machine close the
  latency gap (the next generation of NPU / unified-memory chips
  may halve per-call cost).
- The threat-model assumes paraphrased PII is enough of a real-
  world risk that an async detection mode is worth the operational
  complexity. Today the deterministic stages cover the categories
  CISOs prioritize; paraphrased-PII coverage is a value-add, not a
  load-bearing requirement.

## What was removed

- `src/promptguard/detectors/llm_judge.py` (module).
- `LLMJudgeDetector`, `LLMJudgeNotImplemented` exports from
  `src/promptguard/detectors/__init__.py`.
- `policy.detectors.llm_judge` field from `core/policy.py`.
- The `if policy.detectors.llm_judge.enabled` branch in
  `core/pipeline_factory.py`.
- `tests/unit/test_llm_judge.py`.
- `docs/llm-judge.md`.
- `llm_judge: { enabled: false }` stanzas from every shipped
  policy and from doc / test fixtures.

DEC-018 (LLM judge real impl) and DEC-019 (per-rule audit_only +
LLM judge validation pending) are superseded by this DEC for the
judge component. The audit-writer half of DEC-018 and the per-rule
audit_only half of DEC-019 are unaffected and remain in force.

## Implementation notes for revisitation

If the judge is reintroduced:

1. Use the v2 prompt template from this validation (with the
   three few-shot examples and the explicit liberal-flagging
   instruction). It is the prompt that produced 100% recall lift.
2. Treat a >= 7B class model as the floor. Smaller models showed
   either zero detections (1.5-3B with strict prompt) or 64% FP
   on clean prose (1.5B with permissive prompt).
3. Do not place the judge on the synchronous request path. The
   operating mode should be async / batch / offline, called from
   a queue consumer that scans audit-eligible requests after the
   user has already received their response.
4. Maintain the determinism contract (`temperature: 0`, `seed: 0`)
   so tests can pin behavior across runs.
5. Re-run the four-criteria validation harness before shipping.
   Do not relax the latency gate without owner signoff.

The v2 prompt template (preserved here for the next attempt):

```
You are a privacy classifier inspecting user text for PII or
sensitive data.

Flag ANY of the following, even when partial, paraphrased, or
written conversationally:
- Personal names (Sarah, McKenzie, Tom, Carlos, Aunt Marlene,
  mother's maiden name)
- Addresses, neighborhoods, landmarks, apartment / building references
- Phone numbers, even fragments or area codes
- Email addresses or patterns describing them
- Dates of birth, medical history, diagnoses, hospital admissions
- Account numbers, routing numbers, license plates, MRNs, SSN
  fragments, passwords
- Internal codenames, employee IDs, customer IDs, project names
  tied to a real org
- Schools, employers, doctors, family relationships when they
  identify a real individual

Be liberal. If a span COULD plausibly identify or describe a real
person's protected attribute, flag it. False positives at this
stage are acceptable; missing PII is not.

For each flagged span return a JSON object with three fields:
  "category": one of private_name, private_address, private_phone,
              email, account_number, private_key, cloud_api_key,
              database_url, jwt, secret, domain, internal_ip,
              customer_name, other
  "start": 0-based inclusive char offset
  "end":   0-based exclusive char offset

Return ONLY a JSON array of these objects. No prose, no explanation.
Empty array [] only if the input contains no protected content of
any kind.

EXAMPLES:

Input: My colleague Bob lives near the old factory.
Output: [{"category":"private_name","start":12,"end":15},
         {"category":"private_address","start":21,"end":44}]

Input: Help me write a Python decorator.
Output: []

Input: Patient Smith, DOB Aug 14 1979, admitted with chest pain.
Output: [{"category":"private_name","start":8,"end":13},
         {"category":"other","start":19,"end":30}]

NOW CLASSIFY:

INPUT:
{0}

OUTPUT:
```
