# DEC-017: Formalize DetectorAdapter and PolicyAdapter ABCs; Purview / ICAP stubs

**Date:** 2026-05-04
**Status:** Accepted
**Phase:** v1 (adapter framework completion)
**Author:** Claude Code (autonomous)

---

## Context

v1 shipped reference adapters as duck-typed Protocols (`Detector`,
`PolicyAdapter`). They worked. But contributors adding a new detector
or policy source had no single place documenting the contract; tests
were per-adapter rather than parametrized; the LLMJudgeDetector existed
only in a stub file with no class.

the v1 plan: formalize the abstract base classes, document the
contracts, audit existing implementations against the contracts, and
ship Purview + ICAP as PoC stubs with sample fixtures so the adapter
framework is observable in the codebase.

## Options considered

### Option 1: Keep `Protocol` base; add documentation
- Pros: No code change; static-typing nominally correct.
- Cons: No runtime ABC enforcement. A new adapter that misnames `name`
  or omits `detect` does not get caught at import time. Conformance
  tests would still need to enumerate every adapter.

### Option 2: Convert Protocols to abstract base classes (chosen)
- Pros: Subclass relationship is checkable at runtime via `issubclass`.
  Conformance tests parametrize over the four shipped classes and the
  ABC itself enforces the method shape. New adapters get import-time
  errors if they forget to implement `detect` / `load`.
- Cons: Adapters now MUST inherit explicitly. Existing duck-typed code
  would not work. We control all the existing code; this is fine.

### Option 3: Build a plugin / entry-point registration system
- Pros: Adapters could be packaged separately and discovered at
  runtime via `importlib.metadata.entry_points()`.
- Cons: Overkill for v1's four-adapter footprint. Adds a layer of
  indirection that does not pay off until contributors are publishing
  third-party packages, which is post-v1.1 at the earliest.

## Decision

Convert `Detector` Protocol to `DetectorAdapter` ABC; convert
`PolicyAdapter` Protocol to a real ABC. Add per-adapter audit-conformance
test files that parametrize over every shipped adapter and assert:

- subclasses the ABC,
- `name` class attribute is lowercase + no spaces,
- output type / shape invariants hold.

Ship `LLMJudgeDetector` as a v1 skeleton class that subclasses the ABC
and refuses to instantiate (raises `LLMJudgeNotImplemented` with the
exact escape-hatch message). The pipeline factory already refuses to
construct one; the class refuses too. Belt + braces. Real implementation
lands v1.

Ship `PurviewDLPPolicy` as a real adapter that loads a JSON SIT export
and translates to PromptGuard `Policy`. Sample fixture
`tests/fixtures/purview/sample-sit-export.json` has 5 information
types covering categories Mahdi typically deals with. The Microsoft
Graph API fetch is documented as v1.1 work via a `_v1_1_todo` key in
the fixture itself.

Ship `ICAPPolicy` as a real adapter that parses a recorded ICAP
response with a simple tab-separated rule body. Sample fixture
`tests/fixtures/icap/sample-rules-response.txt` mirrors the wire shape.
Vendor-specific bodies (Symantec, Forcepoint, Trellix) translate to
this PromptGuard intermediate format inside their respective v1.1
adapter implementations; v1 only ships the intermediate-format parser.

Add `promptguard.policies.factory.build_policy_adapter_from_env` so
operators can swap policy sources via `PROMPTGUARD_POLICY_SOURCE`
without touching code. The `PromptGuardHook.from_env` wires this up.

## Consequences

### Enables
- One-line operator config swap: `PROMPTGUARD_POLICY_SOURCE=purview_dlp`
  or `=icap` swaps policy source, no code change.
- Conformance suites at `tests/unit/test_detector_adapter_contract.py`
  and `tests/unit/test_policy_adapters.py` automatically check every
  shipped adapter. Adding a new adapter is one parametrize entry
  away from full conformance coverage.
- Equivalence tests prove Purview / ICAP / YAML translations of the
  same intent produce identical action decisions.
- Schema errors in Purview / ICAP raise `PolicySchemaError` with the
  same multi-line message format as `LocalYAMLPolicy`, so the operator
  experience is consistent across sources.

### Constrains
- `name` is now `ClassVar[str]` not just an instance attribute.
  Adapters must declare it at class scope (this is what we wanted
  anyway).
- The Purview adapter requires a 1:1 category mapping from input
  `informationTypes` to PromptGuard categories. A vendor schema with
  multiple SITs that all roll up to "private_key" (e.g. RSA, EC, OpenSSH
  separately) needs to be flattened upstream of the adapter. v1.1 may
  add a category-merging strategy.

### Revisit if
- A third-party packaged adapter ships that wants entry-point discovery.
  At that point we add an `importlib.metadata` registry alongside the
  hardcoded factory map.
- A real Purview tenant has a SIT shape that the v1 fixture format does
  not capture. Update the fixture and the adapter; the structure should
  generalize, but vendor-specific details may surface.

## Implementation notes

- `DetectorAdapter` lives in `src/promptguard/detectors/base.py`. The
  contract is documented at module level with four binding rules.
  `RegexDetector`, `OPFDetector`, `PresidioDetector`, `LLMJudgeDetector`
  all subclass it; `name` is `ClassVar[str]`.
- `PolicyAdapter` lives in `src/promptguard/policies/base.py`. The
  contract is documented at module level with three binding rules.
  `LocalYAMLPolicy`, `GitManifestPolicy`, `PurviewDLPPolicy`,
  `ICAPPolicy` all subclass it.
- `factory.build_policy_adapter_from_env` is the one place that knows
  every shipped policy adapter. The hook calls it during startup; the
  reloader could also call it on hot-reload, but the v1 reloader still
  re-loads the same adapter type (a hot-reload that swaps adapter type
  is a v1.1 concern).
- 22 conformance + Purview + ICAP tests in
  `tests/unit/test_policy_adapters.py`. 21 conformance tests in
  `tests/unit/test_detector_adapter_contract.py`. All green at 175 / 175
  total.
