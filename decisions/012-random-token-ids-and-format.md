# DEC-012: Unguessable random token IDs; format `[CATEGORY_<16-hex>]`

**Date:** 2026-05-02
**Status:** Accepted
**Phase:** v1 (reversible TOKENIZE)
**Author:** Claude Code (autonomous)

---

## Context

v1 shipped TOKENIZE with sequential per-category-per-conversation IDs
like `[EMAIL_001]`. The v1 daily report flagged this as a v1.1 hardening
candidate per research-notes section 10 question 5. Mahdi's the v1 plan
escalates this to v1: sequential IDs are a prompt-injection vector and
must be replaced now.

The threat: a malicious LLM could emit `[EMAIL_001]` (or any low-counter
guess) in its response. Our restoration is per-conversation pure string
substitution; if our reverse path encounters a token that *exists in the
current conversation's map*, it would substitute the original value
back into the user-visible text, even though the LLM, not the user,
caused that token to appear. With sequential IDs, the LLM only needs to
guess the counter (low entropy) to surface a value from the same
conversation. With unguessable random IDs, that attack collapses.

This is the threat-model A7 mitigation, formalized.

## Options considered

### Option 1: `secrets.token_hex(8)` -> 16 hex chars
- Pros: 64 bits of entropy. Hex is fully alphanumeric (`[a-f0-9]`),
  trivially JSON-safe, easy to pattern-match in the reverse path with a
  single regex. Plays cleanly with existing `[CATEGORY_*]` tag aesthetic.
- Cons: 16 hex chars is the minimum the brief allows. Not the longest.

### Option 2: `secrets.token_urlsafe(16)` -> ~22 chars (base64 url-safe)
- Pros: More entropy per character.
- Cons: Includes `-` and `_`. Underscore ambiguates the token boundary
  with our `[CATEGORY_<random>]` separator (we'd have to anchor the
  regex more carefully). Pattern less crisp.

### Option 3: `secrets.token_hex(16)` -> 32 hex chars
- Pros: 128 bits of entropy. Matches UUID-class collision probability.
- Cons: Token text is 4x longer than category name in some cases. Eats
  prompt budget. We are not approaching collision probabilities that
  matter at any realistic conversation count.

### Option 4: UUIDv4 string
- Pros: Standard.
- Cons: 36 chars with hyphens; longer than needed and the hyphens cost
  one regex backreference per match.

## Decision

`secrets.token_hex(8)` for 16 hex characters of randomness, format
`[CATEGORY_<16hex>]`. Concrete examples: `[EMAIL_a3f9c1d2e4b56789]`,
`[INTERNAL_IP_4b8e1a92cd3f7e60]`.

Why 16 hex (64 bits) and not more:
- Birthday-attack collision at 64 bits requires ~2^32 = 4 billion tokens
  in the same map to hit one collision pair. We cap a single
  conversation at well under 10k tokens (with 100 conversations max in
  the map per DEC-013, total tokens cap is in the millions, not
  billions).
- The threat we are defending against is *unguessability*, not collision
  resistance. An attacker who can guess 1 token in 2^64 attempts is not
  the worry; that is roughly the cost of guessing a 64-bit symmetric
  key, which is well outside any prompt-injection budget.
- Shorter tokens take less space in user-visible prompts and responses.

Reverse-path regex: `\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]`. Allows future
length growth (the pattern is "16 or more hex"); we never decrease.

JSON safety: hex contains only `[a-f0-9]`, no characters that need
escaping. The bracket-delimited form survives JSON encoding verbatim
inside string values.

## Consequences

### Enables
- A7 (LLM-driven token-emission to manipulate restoration) is mitigated.
  The LLM has no way to guess a token that maps to a value in the
  current conversation's map without 2^63 expected guesses on average.
- Cross-conversation isolation tightens: two distinct conversations
  almost certainly have disjoint token namespaces, so even if a value
  happens to be the same in both (e.g. two engineers paste the same
  email), the tokens differ and conversation B's restorer cannot
  surface conversation A's mapping.

### Constrains
- Tokens are 12 chars longer than the previous sequential form (`_001`
  vs `_a3f9c1d2e4b56789`). Negligible impact on prompt budget in
  practice; flagged for the latency benchmark.
- Tokens are no longer human-meaningful (`_001` had ordinality you could
  read; `_a3f9c1d2e4b56789` is opaque). Audit log carries the
  detector + category + start/end so operators do not need to read
  meaning into the token suffix; the suffix is purely for unguessability.

### Revisit if
- A real-world dataset shows entropy attacks on a 64-bit space we did
  not anticipate. At that point we move to 32 hex (128 bits) which is
  a one-line change.
- Operators ask for human-readable tokens for a debugging workflow. Add
  a debug-mode flag (default off) that uses sequential IDs.

## Implementation notes

- Generation: `secrets.token_hex(8)` inside `TokenMap.issue`.
- Pattern: `_TOKEN_RE = re.compile(r'\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]')`.
  Used by both the request rewriter (idempotency check, do not re-issue
  on already-tokenized text) and the response restorer.
- Existing tests that hardcoded `[EMAIL_001]` updated to match by
  regex via the same pattern.
