# DEC-018: LLM judge real implementation + audit log writer

**Date:** 2026-05-04
**Status:** Accepted
**Phase:** Day 8 (LLM judge + audit writer)
**Author:** Claude Code (autonomous)

---

## Context

Day 8 brief landed two adjacent observability / detection items in one
phase:

1. **LLM judge** as the real fourth-stage detector. Day 6-7 shipped a
   skeleton that refused to instantiate; Day 8 needed the real Ollama-
   backed implementation with timeout handling, robust JSON parsing,
   and a default-off configuration.
2. **Audit log writer** that wires the existing `audit_only` policy
   field to a JSONL on-disk log. Required field set fixed by the brief
   (incl. `pipeline_version` and `policy_hash`); the offending text is
   FORBIDDEN to ever appear in the log.

Both touch policy schema enforcement and operator visibility. Pairing
them in one DEC keeps the tradeoffs visible in one place.

## Options considered (LLM judge)

### Option A: Direct httpx call to Ollama, JSON-only output, tolerant parsing (chosen)
- Pros: One round-trip, one file. Matches the rest of the detector
  framework (httpx-async-client). Tolerant parsing means the judge's
  failures degrade to zero detections, not pipeline failures.
- Cons: Locked to Ollama's `/api/generate` shape. Other local-LLM
  servers (vLLM, llama.cpp server) have different APIs.

### Option B: LangChain or similar library wrapper
- Pros: Provider-agnostic.
- Cons: Heavy dep. We do not need provider abstraction at v1; we ship
  Ollama as the reference local LLM and document the prompt template
  for operators who want to adapt.

### Option C: OpenAI-compatible API (talk to Ollama via its `/v1/chat/completions`)
- Pros: Could reuse our existing OpenAI-style request shape.
- Cons: Ollama's OpenAI-compat layer is tag-along, not first-class.
  `/api/generate` is the supported path.

## Decision (LLM judge)

Option A. `LLMJudgeDetector` posts JSON to `/api/generate` with
`stream: false`, `temperature: 0`, `seed: 0` (determinism contract),
and a structured prompt template. Output is a JSON array of
`{category, start, end}` objects; anything else parses to zero
detections with a warning log.

Failure modes that return zero detections (no exception):
- Timeout (`PROMPTGUARD_LLM_JUDGE_TIMEOUT_S`, default 2s)
- HTTP error from Ollama (any non-2xx)
- Connection refused / DNS / network
- Non-JSON response envelope
- JSON envelope with non-list `response` field
- List items with missing or malformed `category` / `start` / `end`
- Spans out of range or inverted

Determinism: temperature=0 + seed=0 + a fixed prompt template gives
reproducible output on a given Ollama model + version. The contract
(DEC-017 rule 3) is met as far as the model exposes the seed.

Default-off via `detectors.llm_judge.enabled: false`. Pipeline factory
constructs the detector without a runtime readiness probe (unlike OPF
which has a hard-fail probe at startup). Rationale: the LLM judge is a
backstop with tolerant runtime semantics; an unreachable Ollama gives
zero detections rather than refusing to start. Operators see the
warning logs and fix.

## Options considered (audit writer)

### Option A: JSONL file, append-only, lock-serialized (chosen)
- Pros: Stdlib-only. Operator-friendly (every Unix log tool understands
  JSONL). Atomic-append works under POSIX for sub-PIPE_BUF lengths,
  which our event sizes always are. Rotation is a logrotate config away.
- Cons: Operators who want SQL-style queries have to load the JSONL
  into a tool of their choice (`jq`, ClickHouse, etc).

### Option B: SQLite database
- Pros: Queryable in place.
- Cons: New runtime dep on sqlite (stdlib has it, fine), schema
  migration concerns, lock contention concerns. JSONL gives 90% of the
  value with 0% of the lift.

### Option C: External log forwarder (loki, vector, etc)
- Pros: Centralized.
- Cons: Adds a service to the compose stack and a new failure mode
  (forwarder down -> events lost). v1.1 if requested.

## Decision (audit writer)

Option A. JSONL, one event per line, append-only file. Writer
serializes through a lock so multiple in-process callers share one
file; multiple-process append works via OS semantics.

Event schema is fixed by the brief plus `pipeline_version` and
`policy_hash` per the operator's request:

  - `pipeline_version`: from `promptguard.__version__`. Bumps on
    every release.
  - `policy_hash`: SHA-256 of the policy file's bytes, computed once
    at policy load. Reviewers prove "event generated under this exact
    policy" by hashing their own copy of the file.

The offending text is structurally absent: the event dataclass has
no field that carries text content. The only fields that COULD leak
text are `rule` (a string like `email -> MASK`) and `detector` (a
string like `regex:email`); neither comes from the text. A fuzz test
runs 200 iterations with random PII-like strings injected at random
offsets and asserts no sample appears verbatim in the resulting log
file content. This is the no-text invariant the brief required.

Wired into the engine via `policy.audit_only`. When set, the engine
runs in dry-run mode: detections fire, decisions are computed, the
text is forwarded unchanged, one audit event is appended per
non-ALLOW detection. When `audit_only: false`, no audit events are
written even when a writer is wired (so flipping audit_only via
hot-reload changes behavior immediately).

Default destination `./promptguard-audit.log`, configurable via
`PROMPTGUARD_AUDIT_LOG_PATH`.

## Consequences

### Enables (LLM judge)
- Operators can turn on a fourth detection layer with one config line.
- Off-path performance is unchanged (the class is constructed only
  when the policy enables it; the pipeline factory skips construction
  otherwise).
- Tolerance posture means a flaky Ollama does not break the proxy.

### Enables (audit writer)
- Bring-up workflow: drop `audit_only: true` in the policy, observe
  what fires for a day, then enforce.
- Forensic correlation across multiple proxy versions and policy
  revisions via `pipeline_version` and `policy_hash`.

### Constrains (LLM judge)
- Locked to Ollama's `/api/generate`. Other local-LLM servers need
  their own adapter; v1.1 if requested.
- The default prompt template is single-shot. Adversarial inputs that
  manipulate the model's output to suppress findings are possible;
  the default categories list helps, but any LLM-based detector has
  this risk. Mitigation: keep the deterministic stages running.

### Constrains (audit writer)
- JSONL is one line per event; large logs are append-only and not
  pre-indexed. Operators who need queryable storage load the file
  into their tool of choice.
- The fuzz test runs 200 iterations. Stronger guarantees come from
  property-based testing (`hypothesis`); deferring to v1.1 per the
  Day-8 brief's stdlib constraint.

### Revisit if (LLM judge)
- An operator reports that vLLM / llama.cpp / Hugging Face TGI is the
  preferred local-LLM runtime. Add a parallel adapter.
- The default prompt template misses common cases that a tuned
  template catches. Update DEFAULT_PROMPT_TEMPLATE.

### Revisit if (audit writer)
- Operator workflow needs SQL queries against the audit log. Add a
  v1.1 SQLite-backed writer.
- A real PII string appears in the log file under any code path. That
  is a hard regression and gets a same-day fix.

## Implementation notes

- LLM judge: `src/promptguard/detectors/llm_judge.py`. Tests in
  `tests/unit/test_llm_judge.py` (11 cases including timeout, HTTP
  500, malformed output, partial validity, out-of-range spans, unknown
  category, empty input). All run against respx-mocked Ollama; CI never
  reaches a real Ollama.
- Audit writer: `src/promptguard/audit/writer.py`. Tests in
  `tests/unit/test_audit_writer.py` (9 cases including the 200-iteration
  fuzz). Wired into `ActionEngine` via constructor params; wired into
  `PromptGuardHook.from_env` via `PROMPTGUARD_AUDIT_LOG_PATH`.
- The `LLMJudgeNotImplemented` exception class stays exported for
  backwards compat with the Day 6-7 stub-import path; it now subclasses
  `NotImplementedError` but is never raised.
- 195 tests pass total.
