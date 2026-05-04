# DEC-004: Action engine on v1 reports decisions but does not rewrite

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** v1 (scaffold)
**Author:** MahdiHedhli

---

## Context

The validation gate for v1 says: "A simple integration test sends a prompt with PII through the stack and confirms the request reaches the upstream (with PII detection available, even if action engine is stubbed)."

The roadmap (research-notes section 9) places action-engine primitives on v1 (BLOCK/MASK), and v1 for reversible TOKENIZE with streaming. So v1 explicitly does not own the rewrite.

That leaves a question: how complete should the v1 action-engine stub be?

## Options considered

### Option 1: Pure no-op stub (return decisions only)
- Pros: v1 ends fast, scope honored exactly.
- Cons: Nothing exercises the policy lookup path; v1 starts cold.

### Option 2: Full rewrite-capable engine on v1
- Pros: v1 has less to do.
- Cons: Streaming TOKENIZE and the per-conversation token map are explicitly v1 work; doing them here means designing them on v1 with less information than days 3-4 will have.

### Option 3: Decision-only engine with a frozen public shape (chosen)
- Pros:
  - Detectors and tests can be written against a stable contract today.
  - The policy lookup is exercised end-to-end so v1 starts warm.
  - No premature commitment to rewrite mechanics.
- Cons: Two passes touch `engine.py` (v1 stub, v1 full).

## Decision

`ActionEngine.decide(detections)` returns an `ActionOutcome` containing:
- `blocked: bool`
- `decisions: tuple[ActionDecision, ...]` (per-detection action choice)
- `rewritten_text: str | None` (always None on v1; v1 fills it in)
- `block_reason: str | None`

The shape is frozen. v1 lands MASK (and the BLOCK error response). v1 lands TOKENIZE with the per-conversation token map.

## Consequences

### Enables
- v1 integration test exercises detection + policy lookup end-to-end.
- The frozen public shape lets the proxy pre/post hooks be written against a stable contract.

### Constrains
- The `rewritten_text: None` branch is observable in tests and must be handled correctly when callers add their own rewrite logic.

### Revisit if
- v1 implementation reveals that the outcome shape is missing a field (e.g., per-decision rewrite confidence). At that point we extend rather than break.

## Implementation notes

- `decide()` short-circuits `block_reason` to the first BLOCK decision. v1 does not aggregate multiple BLOCK reasons; the audit log will record all detections regardless.
- `ALLOW` is treated as a no-op pass-through; a category that has no policy rule defaults to `ALLOW`.
- Confidence floors are honored at the policy level via `PolicyRule.min_confidence`.
