# DEC-013: ConversationTokenMap eviction (1h TTL + 100-conversation LRU cap)

**Date:** 2026-05-02
**Status:** Accepted
**Phase:** Day 3 (reversible TOKENIZE)
**Author:** Claude Code (autonomous)

---

## Context

Day-3 brief: per-conversation token map storage in-memory dict keyed by
`conversation_id`, evicted by TTL or max-size LRU. "Pick TTL = 1 hour
or 100 conversations, whichever fits memory budget." This decision
records the chosen values and rationale.

Threat-model concern (A6, token-map ledger as attack surface) drives the
upper bounds: an unbounded map is a growing forensic liability. Even if
we never persist it, a long-running proxy accumulates conversational
context that is itself sensitive. The map must shed old state.

## Options considered

### Option 1: TTL only (1 hour, no count cap)
- Pros: Simple. One timestamp per entry.
- Cons: A burst of unique conversation IDs (e.g. an automation agent
  spawning thousands per minute) blows up memory before the TTL fires.

### Option 2: LRU only (100 conversations, no TTL)
- Pros: Hard memory bound.
- Cons: A long-lived rare conversation could keep map entries
  indefinitely, violating the threat-model goal of bounded retention.

### Option 3: Both (chosen)
- Pros: Memory-bounded under burst (LRU) and time-bounded under sparse
  use (TTL). Each entry must survive both checks.
- Cons: One extra timestamp per entry. Acceptable.

## Decision

ConversationTokenMap evicts entries when **either** condition fires:

1. The conversation's last access was more than `TTL_SECONDS = 3600`
   (one hour) ago.
2. The map holds more than `MAX_CONVERSATIONS = 100` distinct conversation
   IDs at the moment of insertion. The oldest by last-access (LRU) is
   evicted to make room.

Eviction runs on every write (issue) and read (restore) under a single
lock. The check is O(N) over expired entries on the write path because
N is bounded at 100.

Memory budget: each conversation holds at most ~1000 distinct values in
practice (a typical prompt has a handful of PII spans; even chat
sessions of dozens of turns with new PII per turn rarely exceed this).
Each entry is a Python str-to-str pair, ~64 bytes overhead with content.
Worst case: 100 conversations * 1000 entries * 256 bytes = 25 MB. The
"normal" case (hundreds of entries per conversation) is well under 5 MB
total. Memory is not the binding constraint; the bounds exist to satisfy
the threat-model retention promise.

Per-conversation lock granularity is single global lock for v1. v1.1 may
move to per-conversation locks if contention becomes measurable.

## Consequences

### Enables
- Bounded retention satisfies threat-model A6.
- Burst protection: memory cannot grow without bound.
- Single-process map: no cross-process state, no on-disk persistence,
  no subpoena-able store beyond a one-hour rolling window per
  conversation.

### Constrains
- A conversation that pauses for more than an hour and resumes will
  see new tokens issued for the same originals (the old map entry
  evicted). Reverse path on responses still in flight returns tokens
  that no longer have a mapping; per the brief's "tokens not in the
  map pass through unchanged" rule, the user sees the raw token. This
  is correct behavior (we never invent mappings) but a workflow
  consideration.
- Operators with long-running multi-day conversations either configure
  `TTL_SECONDS` higher via env override or accept the loss. v1 ships
  with the documented defaults; tuning is an operator concern.

### Revisit if
- A real workload shows a need for longer TTL. The values are exposed
  via env vars (`PROMPTGUARD_TOKEN_MAP_TTL_S`,
  `PROMPTGUARD_TOKEN_MAP_MAX_CONVERSATIONS`) so operators tune without
  recompiling.
- We add server-mode multi-tenancy in v1.1; at that point the map
  becomes per-tenant and bounds are revisited.

## Implementation notes

- `ConversationTokenMap` lives in
  `src/promptguard/actions/tokenize.py` (where TokenMap already lives).
  v1 keeps the original `TokenMap` name but the class now implements
  TTL+LRU and exposes `restore()` as the reverse path.
- Single threading.Lock guards both reads and writes. Tests cover
  concurrent issue + restore.
- Eviction is opportunistic on each call; no background sweeper thread
  in v1. Adding one is a v1.1 task if memory pressure ever shows.
