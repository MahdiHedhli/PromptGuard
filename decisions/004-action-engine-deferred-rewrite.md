# DEC-004: Action engine on Day 1 reports decisions but does not rewrite

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** Day 1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

The validation gate for Day 1 says: "A simple integration test sends a prompt with PII through the stack and confirms the request reaches the upstream (with PII detection available, even if action engine is stubbed)."

The roadmap (research-notes section 9) places action-engine primitives on Day 2 (BLOCK/MASK), and Day 3-4 for reversible TOKENIZE with streaming. So Day 1 explicitly does not own the rewrite.

That leaves a question: how complete should the Day-1 action-engine stub be?

## Options considered

### Option 1: Pure no-op stub (return decisions only)
- Pros: Day 1 ends fast, scope honored exactly.
- Cons: Nothing exercises the policy lookup path; Day 2 starts cold.

### Option 2: Full rewrite-capable engine on Day 1
- Pros: Day 2 has less to do.
- Cons: Streaming TOKENIZE and the per-conversation token map are explicitly Day 3-4 work; doing them here means designing them on Day 1 with less information than days 3-4 will have.

### Option 3: Decision-only engine with a frozen public shape (chosen)
- Pros:
  - Detectors and tests can be written against a stable contract today.
  - The policy lookup is exercised end-to-end so Day 2 starts warm.
  - No premature commitment to rewrite mechanics.
- Cons: Two passes touch `engine.py` (Day 1 stub, Day 2 full).

## Decision

`ActionEngine.decide(detections)` returns an `ActionOutcome` containing:
- `blocked: bool`
- `decisions: tuple[ActionDecision, ...]` (per-detection action choice)
- `rewritten_text: str | None` (always None on Day 1; Day 2 fills it in)
- `block_reason: str | None`

The shape is frozen. Day 2 lands MASK (and the BLOCK error response). Day 3-4 lands TOKENIZE with the per-conversation token map.

## Consequences

### Enables
- Day 1 integration test exercises detection + policy lookup end-to-end.
- The frozen public shape lets the proxy pre/post hooks be written against a stable contract.

### Constrains
- The `rewritten_text: None` branch is observable in tests and must be handled correctly when callers add their own rewrite logic.

### Revisit if
- Day 2 implementation reveals that the outcome shape is missing a field (e.g., per-decision rewrite confidence). At that point we extend rather than break.

## Implementation notes

- `decide()` short-circuits `block_reason` to the first BLOCK decision. v1 does not aggregate multiple BLOCK reasons; the audit log will record all detections regardless.
- `ALLOW` is treated as a no-op pass-through; a category that has no policy rule defaults to `ALLOW`.
- Confidence floors are honored at the policy level via `PolicyRule.min_confidence`.
