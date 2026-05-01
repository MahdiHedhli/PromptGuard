# DEC-023: Greedy longest-first non-overlapping span selection in the action engine

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** Day 10 (independent wire verification)
**Author:** MahdiHedhli

---

## Context

While running the strengthened MITM wire suite (DEC-022) against a freshly
rebuilt stack on 2026-04-30, two of the six canned prompts produced
visibly corrupted upstream bodies:

1. `01-internal-ip` (TOKENIZE):
   `server_ip = [INTERNAL_IP_53a36af3e4f4ed34]IP_53a36af3e4f4ed34], port = 8443`
   The expected token appeared once, immediately followed by a fragment of
   itself spliced onto the trailing characters.

2. `02-email` (MASK):
   `Send the report to[EMAIL_REDACTED]`
   The mask tag was placed but a leading character was eaten and the
   trailing `.` was lost.

Both bugs traced to `_select_outer_spans` in `actions/engine.py`. The
function is responsible for choosing which detection spans to actually
rewrite when multiple detectors fire on the same region of text. The
sequential right-to-left rewrite loop that follows it only produces
correct output when the selected spans are pairwise disjoint: any
overlap, even of length zero in the wrong direction, causes the second
substitution's `text[end:]` slice to refer to text that the first
substitution has already mutated.

The previous selection logic was "longest-first, drop strictly contained
spans." It had two failure modes:

- **Identical spans from independent detectors.** When regex AND presidio
  both flagged the same IP at offsets `[8:16]`, neither span was
  *strictly* contained in the other, so both survived selection. The
  rewrite loop then ran two substitutions over the same offsets,
  producing the doubled-token corruption above. This was reproducible
  in the wire suite because the production container has Presidio
  enabled while my local test environment did not — the bug only
  surfaced once both detector layers were live.

- **Adjacent overlapping spans from a single detector.** OPF returned
  two spans for one email: `[18:38] = ' alice@internal-corp'` and
  `[38:46] = '.example'`. Regex returned the correct `[19:46]`. None of
  the three was strictly contained in another. The previous selection
  kept the regex span AND the second OPF fragment (since `[38:46]`
  starts inside `[19:46]` but ends outside it, so neither contains the
  other). The right-to-left rewrite then mutated `[38:46]` first,
  changing the indices that `[19:46]` referred to, eating one character
  and losing the trailing `.`.

The shared root cause is that "no strict containment" is too weak a
disjointness predicate. Any overlap — identical, contained, partial,
either direction — makes the rewrite incorrect.

## Options considered

### Option 1: Pre-merge overlapping spans into a single span before rewrite
- Pros: zero detections dropped; covers identical, contained, and partial overlap uniformly.
- Cons: when overlapping spans disagree on category (JWT vs SECRET) or
  on action (MASK vs TOKENIZE), there is no good answer for what the
  merged span should produce. Replacement string and audit row would
  need synthetic tie-breaking that papers over the real ambiguity.

### Option 2: Greedy longest-first non-overlapping selection
- Pros: simple, deterministic, total over all overlap shapes. Preserves
  the existing "outer span wins" intuition where it applies (longest
  span is processed first; anything it overlaps is dropped). Selection
  decision is local: each candidate is compared only to already-kept
  spans, so behavior is independent of detection ordering at input.
- Cons: drops shorter overlapping spans, which means the audit log no
  longer reflects every detector that fired on the corrupted region.
  The audit log already records every audit-only detection, and the
  enforcement-side audit is "what was rewritten," not "what every
  detector saw" — so this trade-off is acceptable.

### Option 3: Interval-tree maximum-weight independent set
- Pros: optimal in some objective (maximum total span length, or
  maximum confidence-weighted coverage).
- Cons: overengineering for the actual span counts (single-digit per
  request). Behavior becomes harder to reason about — "why was
  detection X dropped here but kept there" depends on a global
  optimization. Greedy is sufficient and predictable.

## Decision

Adopt option 2: sort candidate `(detection, replacement)` pairs by
`(length DESC, confidence DESC)` and walk the sorted list, keeping each
pair only if its span does not overlap any already-kept span. Two spans
overlap iff `a.start < b.end and b.start < a.end` (the standard
half-open-interval overlap predicate). This single predicate handles
identical, fully-contained, and partial overlap uniformly.

The sequential rewrite loop downstream is unchanged. It still walks the
selected spans right-to-left.

## Consequences

### Enables
- Independent detector layers (regex + presidio + OPF) can flag the
  same region without producing corrupted output. No coordination
  between detectors is required.
- New detector adapters (planned for the adapter framework, DEC-017)
  can be added without thinking about whether their span shapes
  conflict with existing detectors. The selection function absorbs the
  conflict.
- The wire suite now passes positive substitution-shape assertions for
  TOKENIZE and MASK paths, not just BLOCK.

### Constrains
- The audit log's enforcement rows reflect only the spans that were
  actually rewritten. If two detectors both flagged the same region,
  only the chosen one shows in the rewrite audit. Operators who need
  to know "which detector layers fired on this prompt" should look at
  detection-level telemetry, not the rewrite audit.
- Tie-breaking is deterministic but coarse: equal-length spans break
  ties on confidence, then on input order. There is no notion of
  "preferred detector" in the selection function; if that becomes
  desirable, this function is the place to add it.

### Revisit if
- A detector starts emitting spans whose *correct* behavior is "two
  separate substitutions in the same region" (none of our current
  detectors do, and the threat model does not require it).
- Per-request span counts grow large enough that O(N^2) overlap checks
  become measurable. Single-digit counts today; the loop is trivial.

## Implementation notes

- Function: `_select_outer_spans` in `src/promptguard/actions/engine.py`.
- The previous "strict containment" carve-out was:
  `if (k_d.start, k_d.end) != (d.start, d.end) and ... contained ...`
  Removed in this change. The new predicate is the half-open overlap
  test, no exceptions.
- Test: `test_identical_spans_from_two_detectors_dedupe` in
  `tests/unit/test_action_engine.py` covers regex+presidio identical
  spans for an IP. The existing `test_overlapping_spans_outer_wins`
  covers JWT-contains-SECRET partial containment.
- Wire-suite reproduction: bring up the MITM stack
  (`make -C tools/mitm-verify up`) and run `make test`. The summary
  asserts both that literal PII is absent from the upstream body AND
  that the expected token/mask shape is present, so a regression of
  this kind would fail the suite, not just produce a different-looking
  pass.
- The bug was invisible to the unit test suite running in isolation
  because the test environment did not have Presidio enabled
  alongside regex. The production container does. The wire harness is
  what surfaced it. This is exactly the value DEC-022 was meant to
  add.
