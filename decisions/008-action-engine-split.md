# DEC-008: Split action engine into per-action classes; engine becomes dispatcher

**Date:** 2026-05-01
**Status:** Accepted
**Phase:** v1 (action engine + LiteLLM hook)
**Author:** MahdiHedhli

---

## Context

the v1 plan specified one action class per action type at
`src/promptguard/actions/`: `base.py`, `block.py`, `mask.py`, `tokenize.py`,
`engine.py`. v1 shipped a single `engine.py` whose `decide()` method
returned a list of `(detection, action)` decisions without rewriting.

We needed to land:
  - actual MASK rewriting
  - actual TOKENIZE forward path with per-conversation token map
  - BLOCK that collects violations into a structured envelope
  - one engine that ties the three together while preserving the
    "frozen public shape" promise made in DEC-004

## Options considered

### Option 1: One engine class with `if action == ...` branching
- Pros: Smaller surface area; easier to read top-to-bottom.
- Cons: BLOCK / MASK / TOKENIZE have very different state requirements
  (TOKENIZE owns a TokenMap, BLOCK collects violations). Cramming all of
  that into one method gets messy fast and is harder to unit-test in
  isolation.

### Option 2: Per-action class + dispatcher engine (chosen)
- Pros: Each action's invariants live in its own class. TokenizeAction
  owns the TokenMap; BlockAction owns the violation collection. The
  engine is small and only does bucketing and a single right-to-left
  rewrite pass over the union of MASK and TOKENIZE spans.
- Cons: One more file per action. Worth it.

### Option 3: Strategy pattern with a registry and pluggable actions
- Pros: Future-friendly if we ever add a new action type.
- Cons: Premature abstraction. v1 has three actions and they have been
  stable since the threat model was first locked. Add the registry when
  a fourth action is concretely demanded.

## Decision

Chose Option 2. Engine groups detections by the policy-resolved action
into three buckets, then:

1. If the BLOCK bucket is non-empty, run BlockAction and short-circuit.
2. Else, compute MASK and TOKENIZE replacements per detection, drop
   spans contained inside larger spans (outer wins), and apply all
   substitutions in a single right-to-left pass.

A new helper `_select_outer_spans` solves the JWT-vs-secret overlap case:
when both detectors fire, the outer span (JWT) wins and is masked once,
rather than masking the inner secret span and leaving the JWT prefix /
suffix in the rewritten text.

## Consequences

### Enables
- Each action gets its own test file shape.
- TokenMap is owned by TokenizeAction and the engine, not scattered.
- Future post-call response rewriting (v1 reverse path) plugs into
  TokenMap.restore directly without engine changes.

### Constrains
- The "frozen public shape" of `EngineResult` (v1 DEC-004) is now
  load-bearing. v1's `ActionDecision`/`ActionOutcome` are gone; the
  v1 names are `ActionResult`/`EngineResult`. Per CLAUDE.md "Avoid
  backwards-compatibility hacks", we did not export old names.

### Revisit if
- The engine grows enough conditionals to argue for the strategy
  pattern. v1 streaming work is the next likely pressure point.

## Implementation notes

- `src/promptguard/actions/base.py` defines `Action` Protocol,
  `ActionContext`, `ActionResult`, `AuditEntry`, `Violation`.
- `block.py`, `mask.py`, `tokenize.py` are one class each, all
  trivially testable.
- `engine.py` is the dispatcher with the `_select_outer_spans` helper.
- Idempotency works because mask tags `[EMAIL_REDACTED]` and tokens
  `[EMAIL_001]` are not matched by any detector regex; tested in
  `test_action_engine.py::test_mask_is_idempotent_on_retag`.
