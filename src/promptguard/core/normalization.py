"""Span-mapping primitives for adversarial-input normalization.

The normalization layer transforms text so downstream detectors see
de-obfuscated content. Each transformation step records, per
character of the normalized output, where in the ORIGINAL text it
came from. A `SpanMap` is the resulting per-character mapping; it is
the load-bearing data structure of this module.

Why per-character. Decoded chunks (a base64 string that decoded to
"AKIA") share one original range across many normalized characters,
and confusable replacements may differ in length between original
and normalized. A per-character map handles every shape with one
predicate: `position_map[i]` describes where normalized[i] came from.

Half-open intervals throughout: `[start, end)`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CharOrigin:
    """Origin of one normalized character.

    `orig_start` and `orig_end` describe the original-text range that
    this normalized character came from. For `identity`, the range is
    one character wide and is the verbatim source. For `replace`, the
    range is the original character that was replaced (e.g. Cyrillic
    'a' at orig[5..6) replaced by Latin 'a' in normalized). For
    `decode`, the range is the entire encoded chunk that decoded into
    this output character (every output character of a decoded chunk
    shares the same original range).
    """

    orig_start: int
    orig_end: int
    kind: str  # "identity" | "replace" | "decode"


class SpanMap:
    """Per-character map from a normalized text to its original text.

    `entries[i]` is the `CharOrigin` for `normalized[i]`. The map is
    immutable after construction; transformation steps build new maps
    rather than mutating an existing one.
    """

    __slots__ = ("_entries", "_orig_len")

    def __init__(self, entries: list[CharOrigin], orig_len: int) -> None:
        self._entries = tuple(entries)
        self._orig_len = orig_len

    @classmethod
    def identity(cls, text: str) -> SpanMap:
        """Identity map: normalized text equals original text."""
        return cls(
            [CharOrigin(i, i + 1, "identity") for i in range(len(text))],
            orig_len=len(text),
        )

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> tuple[CharOrigin, ...]:
        return self._entries

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        """Map a half-open span `[start, end)` in normalized text back
        to the corresponding half-open span in original text.

        For empty spans (`start == end`), returns a zero-length range
        anchored at the surrounding character's origin (or end-of-text
        if the span is past the last character).

        For spans that touch a decoded chunk, the returned range
        expands to cover the full original encoded chunk; this is the
        correct behavior for rewrite (we replace the whole obfuscated
        substring, not its partial decoded image).
        """
        n = len(self._entries)
        if start < 0 or end < start or end > n:
            raise ValueError(f"span [{start}, {end}) out of bounds for map of length {n}")

        if start == end:
            if n == 0:
                return (0, 0)
            if start == n:
                # span at end-of-string: anchor at end of original
                last = self._entries[-1]
                return (last.orig_end, last.orig_end)
            anchor = self._entries[start]
            return (anchor.orig_start, anchor.orig_start)

        first = self._entries[start]
        last = self._entries[end - 1]
        return (first.orig_start, last.orig_end)


def compose(outer: SpanMap, inner_text: str, inner_to_orig: SpanMap) -> SpanMap:
    """Compose two SpanMaps.

    `inner_to_orig` maps `inner_text` (an intermediate-stage text)
    back to the original text. `outer` maps a new normalized text
    back to `inner_text`. The composition maps the new normalized
    text back to the original text.

    For each entry in `outer`:
      - If the outer entry refers to an `inner_text` range
        `[a, b)`, the composed entry takes the union of original
        ranges via `inner_to_orig.to_original(a, b)`.
      - The `kind` of the composed entry is `decode` if either side
        is `decode`, otherwise `replace` if either side is `replace`,
        otherwise `identity`.
    """
    composed: list[CharOrigin] = []
    for o in outer.entries:
        a = o.orig_start
        b = o.orig_end
        # Map the inner range [a, b) back through inner_to_orig.
        if a == b:
            anchor = inner_to_orig.to_original(a, a)
            os, oe = anchor[0], anchor[1]
        else:
            os, oe = inner_to_orig.to_original(a, b)
        # Lift the kind: any decode dominates; replace dominates identity.
        if o.kind == "decode" or any(
            inner_to_orig.entries[i].kind == "decode"
            for i in range(a, min(b, len(inner_to_orig)))
        ):
            kind = "decode"
        elif o.kind == "replace" or any(
            inner_to_orig.entries[i].kind == "replace"
            for i in range(a, min(b, len(inner_to_orig)))
        ):
            kind = "replace"
        else:
            kind = "identity"
        composed.append(CharOrigin(os, oe, kind))
    return SpanMap(composed, orig_len=inner_to_orig._orig_len)


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Output of `NormalizationDetector.normalize()`.

    `normalized` is the de-obfuscated text. `span_map` lets callers
    project detection spans (computed in `normalized`'s coordinate
    system) back to `original`'s coordinate system, which is what the
    rewrite path needs to substitute against the actual user-visible
    input. `flags` lists the obfuscation classes that fired during
    normalization (empty when input was clean); useful for telemetry
    and threat-model audit.
    """

    original: str
    normalized: str
    span_map: SpanMap
    flags: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.original != self.normalized
