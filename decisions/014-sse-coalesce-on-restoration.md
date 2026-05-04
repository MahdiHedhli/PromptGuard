# DEC-014: Coalesce streaming text deltas during token restoration

**Date:** 2026-05-02
**Status:** Accepted
**Phase:** v1 (reversible TOKENIZE)
**Author:** MahdiHedhli

---

## Context

v1 streaming reverse path needs to handle SSE responses where a token
issued by the proxy can be fragmented across many `content_block_delta`
events. The mock upstream chunks at four-character boundaries to mimic
the worst-case Anthropic behavior, so a token like
`[INTERNAL_IP_a3f9c1d2e4b56789]` is split across roughly eight delta
events. Substituting per-event with a regex finds no complete token.

Two correct designs exist:

1. **Per-event with stateful buffering**: maintain a rolling text buffer
   across events, watch the tail for partial tokens, flush only the
   stable prefix, retain the unstable tail until more deltas arrive.
   This is what the `StreamingRestorer` and `SSEStreamRestorer`
   primitives in `src/promptguard/proxy/streaming.py` already do at
   the text-stream level.
2. **Coalesce on restoration**: parse the entire buffered SSE blob,
   concatenate every `delta.text` (Anthropic) and
   `choices[].delta.content` (OpenAI) into one string, restore tokens
   in the concatenation, and re-emit the events with all text deltas
   collapsed into a single delta carrying the restored full text.

Empirically, LiteLLM's proxy hands our `async_post_call_streaming_iterator_hook`
a single `bytes` chunk containing the entire upstream SSE response
buffered (at least for the mock case). The first design assumes a
per-event drip; the second assumes whole-blob arrival.

## Options considered

### Option 1: Per-event stateful buffering only
- Pros: Theoretically minimal latency overhead because we can flush as
  soon as a stable prefix exists.
- Cons: Empirically, LiteLLM does not give us per-event drip for the
  Anthropic native path. Buffering primitives go unused.

### Option 2: Coalesce-on-restoration only
- Pros: Works correctly with the actual chunk shape LiteLLM gives us.
  The streaming SSE round-trip test passes against the mock with full
  fidelity. Trivially correct because we operate on the concatenated
  text.
- Cons: Collapses many small delta events into one delta event. Clients
  that count delta events get fewer; clients that render incremental
  text see the full restored text in one block instead of
  character-by-character.

### Option 3: Both
- Pros: Per-event when chunks drip, coalesce when chunks arrive whole.
- Cons: Two code paths to maintain. The detector for "is this a complete
  blob or a partial chunk" is brittle.

## Decision

Ship Option 2 in v1. `restore_sse_blob(token_map, conversation_id, sse_bytes)`
parses the SSE blob, concatenates text deltas, restores via
`TokenMap.restore`, and re-emits with all text-bearing events coalesced
into one. The text-stream and per-event primitives
(`StreamingRestorer`, `SSEStreamRestorer`) remain in the codebase and
unit-tested because they are correct and may be the right tool when a
real Anthropic stream drips per-event in production. We pick the right
tool from the iterator hook based on chunk type.

The "many small deltas collapse to one" trade-off is acceptable for
v1. The user-visible final text is correct. Clients that render
incrementally still see the full restored block; the only visible
difference is timing of text-arrival events, not their content.

## Consequences

### Enables
- Streaming TOKENIZE round-trip works end-to-end against the mock and,
  by extension, will work against real Anthropic when the chunk arrives
  whole.
- The text-stream and per-event SSE primitives are still available for
  the case where LiteLLM drips per-event chunks, by adding a chunk-shape
  detector at the iterator-hook layer.

### Constrains
- Clients that subscribe to `content_block_delta` events for purposes
  beyond rendering text (very rare) get fewer events than the upstream
  emitted.
- Streaming back-pressure is whatever LiteLLM gives us. If a real
  Anthropic stream takes 30 seconds and LiteLLM buffers all of it
  before invoking our iterator hook, the user sees 30 seconds of
  silence followed by a single text block. This is a LiteLLM-side
  behavior; PromptGuard does not buffer additional delay.

### Revisit if
- A real Anthropic stream is shown to drip per-event into our hook.
  At that point we add a chunk-shape detector and route partial
  chunks through `SSEStreamRestorer` instead of `restore_sse_blob`.
- A client is shown to depend on the original per-event delta
  cadence for rendering reasons.

## Implementation notes

- `restore_sse_blob` lives in `src/promptguard/proxy/streaming.py`.
  It does not short-circuit on `_TOKEN_RE.search(raw_bytes)` because
  the token suffix may be split across SSE event boundaries by upstream
  chunking; the raw bytes contain JSON envelope characters between
  fragments and the regex will never match a complete token in that
  form. We always parse + concatenate + check.
- The iterator hook in `src/promptguard/proxy/litellm_hooks.py` calls
  `restore_sse_blob` for `bytes`/`str` chunks and falls back to
  in-place attribute walking for typed chunks.
- Tests cover: round-trip with mock chunking at 4 chars (every token
  spans 8 events), clean prompts (no rewrite), and conversation
  isolation (token from convo A passes through untouched in convo B).
