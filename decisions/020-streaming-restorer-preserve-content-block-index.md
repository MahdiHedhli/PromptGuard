# DEC-020: Streaming SSE rebuild preserves content_block index

**Date:** 2026-05-07
**Status:** Accepted
**Phase:** v1 (packaging polish; v1 carryover root-cause)
**Author:** MahdiHedhli

---

## Context

v1 daily report flagged that direct curl + real-Anthropic round-trip
worked cleanly through the proxy, but the same prompts via the `claude`
CLI v2.x errored with `API Error: Content block is not a text block`.
Two streaming-restorer adjustments shipped on v1 (no-op short-circuit
when no tokens needed restoring; preserve event count by emitting empty-
text deltas instead of collapsing) reduced the surface but did not fully
resolve. The the v1 plan allocated a 2-hour timebox to root-cause.

Resolved in 30 minutes inside the window. Hypothesis was right on the
first attempt and the fix is small.

## Root cause

`claude` CLI v2.x sends `extended-thinking` requests. Anthropic's
streaming response then produces multiple content blocks at distinct
`index` values: a thinking block at `index=0` and a text block at
`index=1` (or higher). Each `content_block_start` event declares the
block's index; subsequent `content_block_delta` events for that block
carry the same index.

PromptGuard's `restore_sse_blob` rebuild path called
`_build_anthropic_text_delta_event(text)` which hardcoded
`"index": 0`. When the upstream's text-delta events were at `index=1`
and we replaced them with rebuilt events at `index=0`, the receiving
parser saw a delta at `index=0` whose matching `content_block_start`
declared a `thinking` block, NOT a text block. The CLI correctly
rejected the mismatch with `Content block is not a text block`.

The issue did not surface on direct curl because the v1 mock-
Anthropic upstream and our integration tests did not use extended-
thinking, so all content blocks were at `index=0` and the hardcoded
index happened to match. The CLI exposed the bug because its requests
are extended-thinking-enabled by default.

## Fix

Replace the rebuild's "construct a fresh event with hardcoded index"
path with "deep-copy the original event's payload, swap only the text
field, re-encode preserving every other field." Concrete:

  - `_replace_delta_text(payload, new_text)`: in-place mutation of
    `delta.text` (Anthropic) or `choices[0].delta.content` (OpenAI).
    No-op if neither field is present.
  - `_reencode_event(raw_event, new_payload)`: replace the JSON in the
    `data:` line of an SSE event while preserving the `event:` header
    line and any non-data lines (comments, retry directives) verbatim.

The rebuild loop deep-copies each text-delta event's payload, swaps
the text (full restored text in the first event, empty text in
subsequent events as before), and re-encodes via `_reencode_event`.
The `index`, `delta.type`, surrounding `event:` line, and any other
fields the upstream may add stay intact.

## Test

`tests/unit/test_streaming_restorer.py::test_restore_sse_blob_preserves_index_field`:
constructs an SSE blob where `content_block_start` and
`content_block_delta` events all use `index=1`, runs the restorer with
a known token, and asserts the output retains `"index":1` and never
introduces `"index":0`.

Live test: `claude --print "What network range does the IP 10.0.13.42
fall into? ..." --model claude-sonnet-4-6` against api.anthropic.com
through the proxy now succeeds end-to-end. Asset
`docs/blog-assets/03-real-anthropic-roundtrip.txt` refreshed with the
working capture.

## Consequences

### Enables
- Real `claude` CLI sessions through the proxy. v1 ships with claude-CLI
  compat for the operator workflow that motivated PromptGuard in the
  first place.
- The rebuild path now generalizes: any future Anthropic content-block
  type (image-deltas, citations, future formats) flows through the
  rebuild without code change because we only touch the `text` field.

### Constrains
- The rebuild path now depends on the upstream's payload shape being
  serializable round-trip via `json.loads` -> deepcopy -> `json.dumps`.
  Any upstream extension that uses non-JSON-serializable content
  (none currently exist in the SSE-text path) would break.

### Revisit if
- Anthropic introduces a delta type that mutates the index across
  events within the same content_block (extremely unlikely; the SSE
  protocol explicitly ties index to a content_block).

## Implementation notes

- `src/promptguard/proxy/streaming.py`: `restore_sse_blob`,
  `_replace_delta_text`, `_reencode_event`. The legacy
  `_build_anthropic_text_delta_event` helper stays in the module
  because it is used in the unit tests' construction of canned SSE,
  but is no longer on the rebuild path.
- The fix is opt-in to no behavior change for the existing
  test corpus (mock-Anthropic, all index=0): re-encoded events are
  byte-identical to the previous hardcoded-index emissions on those
  inputs. v1 round-trip tests stay green.
- Real-key claude CLI capture refreshed at
  `docs/blog-assets/03-real-anthropic-roundtrip.txt` with an honest
  note about LLM paraphrase behavior: when the model paraphrases
  (as it did with this prompt), there is no token in the response to
  restore and the user sees the model's example value rather than
  the original. The mock-based assets 01 + 02 remain the cleanest
  visual because the mock deterministically echoes the token.
