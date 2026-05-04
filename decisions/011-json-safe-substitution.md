# DEC-011: JSON-safe substitution via boundary-delimited concatenation

**Date:** 2026-05-01
**Status:** Accepted
**Phase:** v1 (action engine + LiteLLM hook)
**Author:** MahdiHedhli

---

## Context

the v1 plan, point 5: "Detection and substitution operate on string
values inside JSON bodies, not on the JSON envelope. Tokenizing an email
inside a message body must not break the JSON structure."

Both Anthropic and OpenAI request bodies are nested: `messages[i].content`
can be a string or a list of content blocks each with a `text` field;
`system` can be a string or a list; `tool_result` blocks carry an inner
`content` list with `text` blocks. Detection must run only over those
string values and substitutions must land back in those exact paths.

## Options considered

### Option 1: Run detection per string, substitute in place
- Pros: Conceptually simple.
- Cons: Detectors operate on a single concatenated text in the existing
  pipeline. Running them per string means N pipeline calls per request.
  More importantly, the action engine's overlap handling (DEC-008)
  operates on a single string; running per-string would let an overlap
  between two messages slip past.

### Option 2: Concatenate strings with a known boundary, run pipeline
once, split back (chosen)
- Pros: One pipeline call per request. The action engine sees a single
  text and applies its overlap rules consistently. Boundary is chosen
  so it cannot match any detector regex (NUL bytes plus an ASCII tag).
  Splitting back gives us a list whose length must match the list of
  inspected strings; mismatch is a runtime assertion failure.
- Cons: A boundary in the input would corrupt the split. We use NUL
  bytes (`\x00`) which prompts essentially never contain.

### Option 3: Walk the JSON, run detection per-string, accumulate
detections with synthetic global offsets
- Pros: One pipeline call equivalent (each string still calls regex
  separately).
- Cons: Synthetic offsets add bookkeeping. Boundary concatenation gets
  the same result with fewer moving parts.

## Decision

Chose Option 2. Concrete API in `src/promptguard/proxy/messages.py`:

  - `extract_inspectable_strings(body)` walks the request body and
    returns a list of `(path, value)` for every inspected string.
  - Boundary: `\x00\x00PG_BOUNDARY\x00\x00`. Two NULs plus an ASCII
    marker plus two NULs. No prompt or detector regex matches this.
  - `join_for_inspection(strings)` concatenates with the boundary.
  - The pipeline + action engine run over the joined text.
  - `split_after_inspection(joined, n)` splits and verifies the count.
  - `set_at_path(body, path, value)` writes each part back.

Inspected fields, by request shape:

  - `body["messages"][i]["content"]` (str)
  - `body["messages"][i]["content"][j]["text"]` (Anthropic + OpenAI
    structured blocks)
  - `body["messages"][i]["content"][j]["content"][k]["text"]` (Anthropic
    `tool_result` nested)
  - `body["system"]` (str)
  - `body["system"][j]["text"]` (Anthropic structured system)

Tool definitions are not inspected at v1 (a tool description that names
a credential category is the operator's choice). Tool *outputs* arriving
in `tool_result` content are inspected.

## Consequences

### Enables
- One pipeline call per request regardless of how many message blocks.
- The action engine's overlap handling stays correct.
- JSON envelope around the prompts is untouched: `model`, `max_tokens`,
  `temperature`, `metadata`, `tool_choice`, and any other top-level keys
  are byte-identical between input and rewritten output. Tested.

### Constrains
- A pathological prompt containing the literal boundary would corrupt
  the split. We accept this because (a) the boundary contains NUL bytes
  which are not legal in many text encodings the LLM client uses, and
  (b) `split_after_inspection` raises if the count mismatches, so the
  failure is loud, not silent.

### Revisit if
- A future content type (image OCR text? PDF extraction?) needs JSON
  rewriting too. The boundary trick generalizes.
- A real-world prompt is shown to contain NUL-prefixed text. At that
  point we switch the boundary to a longer random sentinel allocated
  per request.

## Implementation notes

- `tests/unit/test_litellm_hook.py` covers the four shapes (string
  content, Anthropic content blocks, OpenAI vision-style content blocks,
  tool_result nested) and verifies idempotency on already-rewritten
  bodies.
- The integration test `test_hook_does_not_disturb_envelope_keys`
  asserts every top-level key except `messages` is byte-identical
  through the hook.
