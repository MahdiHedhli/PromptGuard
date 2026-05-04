# DEC-024: NormalizationDetector as a pre-detection canonicalization layer

**Date:** 2026-05-02
**Status:** Accepted
**Phase:** v1.1 phase 2 (encoding-evasion defense)
**Author:** MahdiHedhli

---

## Context

The v1 detection stack (regex + OPF + Presidio) operates on raw input
bytes. A user pasting an AWS access key into a prompt with zero-width
characters injected between every other character defeats the regex
layer trivially: the shape regex anchors on contiguous ASCII, and a
zero-width-injected credential is no longer contiguous. The same holds
for confusable substitution (Cyrillic 'а' for Latin 'a'), HTML entity
encoding (`&#x41;` for `A`), URL percent-encoding, and base64-wrapping.

Other inline-detection prototypes ship a normalization layer in their
v0; the v1.1 review surfaced this as a structural gap in PromptGuard.
The threat-model entry for this attack class is A8 in
`docs/threat-model.md`.

The defense must:

1. Canonicalize input in a way that downstream detectors see a single
   normal form regardless of encoding. The Unicode-recommended form
   for security comparison is NFKC (Unicode TR #15, NIST SP 800-63B
   Appendix A).
2. Preserve a span map from the canonical text back to the original
   input, so when a detector reports "AWS key at offset N in canonical
   text" the rewrite path can substitute against the user-visible
   original (BLOCK / MASK / TOKENIZE all act on the original).
3. Add minimal latency to the per-request pipeline.

## Options considered

### Option 1: Inline canonicalization inside each detector
Each detector independently strips zero-width chars / NFKCs / decodes
encoded forms before applying its own pattern.
- Pros: no architectural change to the pipeline.
- Cons: duplicates canonicalization across regex + OPF + Presidio +
  any future detector. Different detectors will canonicalize to
  slightly different forms over time, causing detection drift. Span
  mapping has to be re-implemented per detector.

### Option 2: NormalizationDetector as a pre-detection layer
A new layer runs first; produces canonical text + span map. The
pipeline runs every other detector against canonical text and remaps
their spans to the original via the span map.
- Pros: one canonicalization implementation, one span-mapping
  algorithm, one telemetry source ("which encodings were seen on
  this prompt"). Adding new sanitization steps does not touch
  individual detectors. The canonical form is the same input every
  detector sees, so detection coverage scales linearly.
- Cons: introduces a span map as a load-bearing data structure,
  which is the kind of thing that breaks subtly if not tested.

### Option 3: Run detectors twice, once on raw and once on canonical
Treat canonicalization as opportunistic: the second pass is a
fallback when the first finds nothing.
- Pros: never misses a "raw" detection that happened to be lost in
  canonicalization.
- Cons: doubles per-request cost in the common case. Two detection
  sets need to be merged, and the merge is exactly the span-mapping
  problem the second option already has to solve. Strictly worse.

## Decision

Option 2. `NormalizationDetector` lives at
`src/promptguard/detectors/normalizer.py` and runs in
`DetectionPipeline._prepare()` before the detector fan-out.
Sanitization steps, in order:

1. **NFKC.** `unicodedata.normalize("NFKC", text)`. Folds compatibility
   variants (fullwidth Latin, Roman numeral letters, certain
   confusables that have a Unicode compatibility decomposition) to
   their canonical form. Per-character invocation of NFKC keeps the
   span map exactly aligned to input characters.
2. **Default-ignorable stripping.** Drop characters in our hard-coded
   shortlist (ZWSP, ZWNJ, ZWJ, BOM, Hangul fillers, RTL/LTR marks,
   Mongolian variation selectors, all of the U+2060 word-joiner
   neighborhood) plus any character whose Unicode general category is
   Cf ("Format"). The shortlist plus the Cf fallback covers the
   default-ignorable code-point set defined in UAX #44, scoped to
   characters that are visually invisible.
3. **HTML entity decoding.** `html.unescape` over `&[#x]?...;` matches.
4. **URL percent-decoding.** `urllib.parse.unquote` over contiguous
   `%XX%XX...` runs. Operates only on contiguous percent-encoded runs
   so a stray `%` in prose does not mangle the input.
5. **Base64 nested-content decoding.** For runs of [A-Za-z0-9+/]{16+}
   that decode to printable ASCII, replace with the decoded form.
   Recursion cap of 3 inside `NormalizationDetector.normalize` so a
   base64-of-URL-encoded payload (or vice versa) gets fully unwrapped
   while pathological cases are bounded.

The span map is per-character: `position_map[i]` records the original
range from which `normalized[i]` came, plus a `kind` tag
(`identity` / `replace` / `decode`). Mapping a span `[a, b)` in
normalized text returns `[position_map[a].orig_start,
position_map[b-1].orig_end)`. For decoded chunks every output
character of the chunk shares the same original range, so any span
that touches the chunk expands to cover the full original encoded
form. This is the right behavior for rewrite: BLOCK / MASK /
TOKENIZE substitute the entire user-visible obfuscation, not its
partial decoded image.

## Consequences

### Enables
- Encoding-evasion attacks (A8) are defeated for the encodings
  enumerated above without per-detector special-casing.
- New detectors added to the pipeline automatically benefit from the
  same canonicalization and span-remapping.
- Detection coverage on legitimate inputs that happen to contain
  encoded data improves: a logged credential inside a base64 blob
  or a percent-encoded URL gets caught.
- Operator telemetry: `NormalizationResult.flags` exposes which
  sanitization steps fired, which is useful for "show me prompts
  that contained encoded payloads."

### Constrains
- Detector output coordinates must be remapped before the action
  engine sees them. The remap happens inside `DetectionPipeline.run`
  so detectors stay coordinate-system-agnostic.
- The span map's "decoded chunk expands to full original range"
  behavior means the rewrite is conservative: a partial-overlap span
  on a decoded chunk substitutes the whole chunk. Operators who want
  finer-grained substitution would need a different policy; this
  matches the threat-model intent (cover the full obfuscation).
- The base64 decoder treats only printable-ASCII decodings. Binary
  payloads (PE files embedded in prompts) are out of scope for the
  text-detection pipeline; they would be a Phase-future scanning
  workstream.

### Revisit if
- A legitimate use case emerges where users paste base64-encoded
  binary that is incidentally printable but should not be scanned
  recursively (we have not seen such a case in v1).
- Confusables not covered by NFKC compatibility decomposition (the
  Unicode CLDR confusables.txt has thousands of entries; NFKC covers
  a subset) become a real attack pattern. The CLDR data ships under
  the Unicode license, compatible with Apache 2.0; vendoring it is
  the next step if needed.
- Latency of the base64 step becomes measurable on long prompts. The
  upper bound on `_BASE64_RE` is 2048 chars per match, which keeps
  the worst-case linear in prompt length.

## Implementation notes

- Public surface: `NormalizationDetector`, `NormalizationConfig` from
  `promptguard.detectors.normalizer`. The pipeline factory wires the
  default config when `policy.detectors.normalization.enabled` is
  true (separate adapter wiring task).
- The span-map primitives live in `promptguard.core.normalization`
  (`SpanMap`, `CharOrigin`, `NormalizationResult`, `compose`). The
  detector module re-exports `compose` for callers that need to
  build maps manually.
- Tests: `tests/unit/test_normalization.py`. 25 tests covering each
  sanitization step, idempotency, span-map correctness across
  identity / replace / decode kinds, a 200-trial fuzz on random
  obfuscation combinations, and pipeline integration that asserts a
  zero-width-injected marker is invisible without normalization but
  caught with normalization, with the reported span pointing at the
  original obfuscated range.
- Latency on a representative mix of prompts (n=2000, M3 Pro,
  CPython 3.11): avg 0.072 ms, p50 0.048 ms, p95 0.192 ms, p99
  0.213 ms. Well under the 1 ms p95 budget; the canonicalization
  layer is essentially free at the per-request scale.
- Test fixtures use clearly-fake credential-shaped tokens
  (`AKIAFAKE_FAKE_FAKE_FAKE`) so test data is unambiguously
  synthetic.
