"""Defensive input sanitization for the detection pipeline.

This module implements the input-canonicalization layer that runs
BEFORE the regex / OPF / Presidio detectors. It exists so that
downstream detectors see a single canonical form of any sensitive
data the user pasted into a prompt, regardless of which Unicode
encoding, character substitution, or transport encoding the input
arrived in.

This is defensive code on the receive side of a security boundary.
It is the same family of input-sanitization patterns used in:

  * IDN registrar libraries (Unicode normalization for visual
    spoofing defense), see RFC 5895 (IDNA case-folding) and
    Unicode TR #36 (Unicode security mechanisms).
  * Email validation libraries that strip default-ignorable code
    points before comparing addresses.
  * Web application firewalls that decode percent-encoded and
    HTML-entity-encoded request payloads before pattern matching.
  * Enterprise DLP products (Microsoft Purview, Symantec DLP, McAfee
    DLP) that recursively scan nested encoded content (base64,
    quoted-printable) so credentials hidden inside encoded payloads
    do not slip past their pattern engines.

The output is a `NormalizationResult` with three fields:

  * `normalized`: the canonicalized text. Downstream detectors run
    against this. Identical to `original` when the input was already
    canonical.
  * `span_map`: per-character map from `normalized` back to
    `original` (see `promptguard.core.normalization.SpanMap`). When
    a downstream detector reports a span in `normalized`, the
    rewrite path uses `span_map.to_original(...)` to rewrite the
    user-visible text rather than the canonicalized form.
  * `flags`: which sanitization steps actually changed the input.
    Useful for telemetry; the operator may want to know that an
    incoming prompt contained encoded payloads.

Idempotency: re-running normalization on an already-normalized
input is a no-op. Tests assert this on a fuzzed corpus.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass

from promptguard.core.normalization import (
    CharOrigin,
    NormalizationResult,
    SpanMap,
    compose,
)

# --------------------------------------------------------------------------
# Default-ignorable code points
# --------------------------------------------------------------------------

# Unicode Default_Ignorable_Code_Point (DICP). Defined in UAX #44; the
# canonical list is published in DerivedCoreProperties.txt. We hard-code
# the set the security community considers high-risk for visual spoofing
# of textual content (zero-width and BOM-class characters). This is the
# same shortlist used by the Twisted Strange Loop / IDN-defense write-ups
# and by the homoglyph_attack_detection libraries on PyPI.
_DEFAULT_IGNORABLE: frozenset[str] = frozenset(
    [
        "­",  # Soft hyphen
        "͏",  # Combining Grapheme Joiner
        "ᅟ",  # Hangul Choseong Filler
        "ᅠ",  # Hangul Jungseong Filler
        "឴",  # Khmer Vowel Inherent Aq
        "឵",  # Khmer Vowel Inherent Aa
        "᠋",  # Mongolian Free Variation Selector One
        "᠌",  # Mongolian Free Variation Selector Two
        "᠍",  # Mongolian Free Variation Selector Three
        "᠎",  # Mongolian Vowel Separator
        "​",  # Zero-Width Space
        "‌",  # Zero-Width Non-Joiner
        "‍",  # Zero-Width Joiner
        "‎",  # Left-To-Right Mark
        "‏",  # Right-To-Left Mark
        "‪",  # Left-To-Right Embedding
        "‫",  # Right-To-Left Embedding
        "‬",  # Pop Directional Formatting
        "‭",  # Left-To-Right Override
        "‮",  # Right-To-Left Override
        "⁠",  # Word Joiner
        "⁡",  # Function Application
        "⁢",  # Invisible Times
        "⁣",  # Invisible Separator
        "⁤",  # Invisible Plus
        "⁦",  # Left-To-Right Isolate
        "⁧",  # Right-To-Left Isolate
        "⁨",  # First Strong Isolate
        "⁩",  # Pop Directional Isolate
        "⁪",  # Inhibit Symmetric Swapping
        "⁫",  # Activate Symmetric Swapping
        "⁬",  # Inhibit Arabic Form Shaping
        "⁭",  # Activate Arabic Form Shaping
        "⁮",  # National Digit Shapes
        "⁯",  # Nominal Digit Shapes
        "﻿",  # Byte Order Mark / Zero-Width No-Break Space
    ]
)


def _is_default_ignorable(ch: str) -> bool:
    """Return True if `ch` is a default-ignorable code point.

    Combines our hard-coded shortlist (above) with a fallback to the
    Unicode `Cf` (Format) general category, which covers other
    invisible formatting characters not enumerated in the shortlist.
    """
    if ch in _DEFAULT_IGNORABLE:
        return True
    return unicodedata.category(ch) == "Cf"


def _strip_default_ignorable(text: str, base_map: SpanMap) -> tuple[str, SpanMap]:
    """Drop default-ignorable code points from `text`.

    `base_map` is the span map for `text` relative to the original
    input. We return the post-strip text and the composed span map
    that maps stripped output back through `base_map` to the
    original.
    """
    out_chars: list[str] = []
    out_origins: list[CharOrigin] = []
    for i, ch in enumerate(text):
        if _is_default_ignorable(ch):
            continue
        out_chars.append(ch)
        # The stripped char came from index `i` of `text`. Keep its
        # origin from the base map; mark `kind` as identity since
        # this step is a structure-preserving filter.
        origin = base_map.entries[i]
        out_origins.append(origin)
    new_text = "".join(out_chars)
    new_map = SpanMap(out_origins, orig_len=base_map._orig_len)
    return new_text, new_map


# --------------------------------------------------------------------------
# NFKC canonicalization
# --------------------------------------------------------------------------


def _apply_nfkc(text: str, base_map: SpanMap) -> tuple[str, SpanMap, bool]:
    """Apply NFKC compatibility canonicalization.

    NFKC is the Unicode-recommended normalization for security
    comparison (Unicode TR #15, NIST SP 800-63B Appendix A). It
    folds compatibility characters to their canonical form: Roman
    numeral 'Ⅴ' to 'V', fullwidth 'ＡＢＣ' to 'ABC', certain
    confusable Cyrillic/Greek letters to their Latin canonical
    form when they share a compatibility decomposition.

    Returns (new_text, new_map, changed). When `changed` is False,
    the input was already in NFKC form and we return identity.

    Span mapping for NFKC requires per-character composition tracking
    because NFKC may change the length of substrings (e.g. one
    composed character may decompose into two). We compute the
    mapping by applying NFKC to each input character independently
    and concatenating the results, preserving origin per output
    character. This is a slight over-canonicalization compared to
    block-level NFKC but is correct for security comparison and
    matches what idnlib does.
    """
    if unicodedata.is_normalized("NFKC", text):
        return text, base_map, False

    out_chars: list[str] = []
    out_origins: list[CharOrigin] = []
    changed = False
    for i, ch in enumerate(text):
        canonical = unicodedata.normalize("NFKC", ch)
        if canonical != ch:
            changed = True
            kind = "replace"
        else:
            kind = base_map.entries[i].kind
        # Each canonical character inherits the origin of the input
        # character it came from. If NFKC produced N output chars
        # from one input char, all N share the same origin.
        origin = base_map.entries[i]
        for _ in canonical:
            out_origins.append(CharOrigin(origin.orig_start, origin.orig_end, kind))
        out_chars.append(canonical)
    return "".join(out_chars), SpanMap(out_origins, orig_len=base_map._orig_len), changed


# --------------------------------------------------------------------------
# HTML entity decoding
# --------------------------------------------------------------------------

# Match named entities (`&amp;`) and numeric entities (`&#NN;` / `&#xHH;`).
# The trailing semicolon is required; HTML5's "missing-semicolon" leniency
# is not in scope at this layer.
_HTML_ENTITY_RE = re.compile(r"&(?:#x?[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")


def _decode_html_entities(text: str, base_map: SpanMap) -> tuple[str, SpanMap, bool]:
    """Decode HTML/XML character entities.

    Standard input-sanitization step used by every web-application
    firewall and by every HTML-aware DLP scanner. Encoded forms
    like `&#x41;` (capital A) hide raw characters from naive pattern
    matchers. We decode and let downstream detectors see the literal
    form.
    """
    out_chars: list[str] = []
    out_origins: list[CharOrigin] = []
    changed = False
    last_end = 0
    for m in _HTML_ENTITY_RE.finditer(text):
        s, e = m.span()
        # Copy the gap before the entity verbatim.
        for j in range(last_end, s):
            out_chars.append(text[j])
            out_origins.append(base_map.entries[j])
        # Decode the entity.
        decoded = html.unescape(m.group(0))
        if decoded != m.group(0):
            changed = True
            # The decoded character(s) inherit the origin range of the
            # full entity (e..g. all 6 chars of "&#x41;" map to the same
            # original range). Mark as "decode" so downstream span
            # remapping knows this region was transformed.
            os = base_map.entries[s].orig_start
            oe = base_map.entries[e - 1].orig_end
            for ch in decoded:
                out_chars.append(ch)
                out_origins.append(CharOrigin(os, oe, "decode"))
        else:
            # html.unescape did not recognize the entity; pass it through.
            for j in range(s, e):
                out_chars.append(text[j])
                out_origins.append(base_map.entries[j])
        last_end = e
    # Tail.
    for j in range(last_end, len(text)):
        out_chars.append(text[j])
        out_origins.append(base_map.entries[j])
    return "".join(out_chars), SpanMap(out_origins, orig_len=base_map._orig_len), changed


# --------------------------------------------------------------------------
# URL percent-decoding
# --------------------------------------------------------------------------

_PERCENT_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _decode_url(text: str, base_map: SpanMap) -> tuple[str, SpanMap, bool]:
    """Percent-decode URL-encoded runs.

    Standard sanitization step shared with web application firewalls.
    Operates only on contiguous percent-encoded runs (`%XX%XX...`)
    so we do not mangle prose containing a stray `%` character.
    """
    out_chars: list[str] = []
    out_origins: list[CharOrigin] = []
    changed = False
    last_end = 0
    for m in _PERCENT_RE.finditer(text):
        s, e = m.span()
        for j in range(last_end, s):
            out_chars.append(text[j])
            out_origins.append(base_map.entries[j])
        encoded = m.group(0)
        try:
            decoded = urllib.parse.unquote(encoded, errors="strict")
        except UnicodeDecodeError:
            decoded = encoded
        if decoded != encoded:
            changed = True
            os = base_map.entries[s].orig_start
            oe = base_map.entries[e - 1].orig_end
            for ch in decoded:
                out_chars.append(ch)
                out_origins.append(CharOrigin(os, oe, "decode"))
        else:
            for j in range(s, e):
                out_chars.append(text[j])
                out_origins.append(base_map.entries[j])
        last_end = e
    for j in range(last_end, len(text)):
        out_chars.append(text[j])
        out_origins.append(base_map.entries[j])
    return "".join(out_chars), SpanMap(out_origins, orig_len=base_map._orig_len), changed


# --------------------------------------------------------------------------
# Recursive nested-content inspection (base64)
# --------------------------------------------------------------------------

# Conservative lower bound on length: a 16-char base64 string decodes to
# 12 bytes of payload, which is the floor at which an embedded credential
# becomes interesting. Below 16 chars the false-positive rate explodes
# (any short alphanumeric run looks like base64). Cap on length keeps a
# pathological all-base64-shaped input bounded.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,2048}={0,2}")


def _looks_like_decodable(b: bytes) -> bool:
    """Return True if a candidate base64 payload looks like printable
    text after decoding.

    We use this to filter out runs that decode to opaque binary, which
    are not useful to scan with our text-based detectors.
    """
    if not b:
        return False
    printable = sum(1 for byte in b if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D))
    return printable / len(b) >= 0.9


def _decode_nested_base64(
    text: str, base_map: SpanMap
) -> tuple[str, SpanMap, bool]:
    """Decode embedded base64 runs that decode to printable ASCII.

    Mirrors the nested-content inspection step in enterprise DLP
    products (Purview, Symantec DLP). The recursion cap is enforced
    by `NormalizationDetector.normalize`, not by this function; we
    perform one pass per call.
    """
    out_chars: list[str] = []
    out_origins: list[CharOrigin] = []
    changed = False
    last_end = 0
    for m in _BASE64_RE.finditer(text):
        s, e = m.span()
        candidate = m.group(0)
        # Pad to a multiple of 4 if needed.
        padded = candidate + "=" * ((4 - len(candidate) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            # Not a valid base64 chunk; pass through.
            for j in range(last_end, e):
                out_chars.append(text[j])
                out_origins.append(base_map.entries[j])
            last_end = e
            continue
        if not _looks_like_decodable(decoded_bytes):
            for j in range(last_end, e):
                out_chars.append(text[j])
                out_origins.append(base_map.entries[j])
            last_end = e
            continue
        # Copy gap.
        for j in range(last_end, s):
            out_chars.append(text[j])
            out_origins.append(base_map.entries[j])
        # Replace the encoded run with its decoded form. All decoded
        # characters share the original range of the encoded run.
        try:
            decoded = decoded_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            decoded = decoded_bytes.decode("latin-1", errors="replace")
        os = base_map.entries[s].orig_start
        oe = base_map.entries[e - 1].orig_end
        for ch in decoded:
            out_chars.append(ch)
            out_origins.append(CharOrigin(os, oe, "decode"))
        changed = True
        last_end = e
    for j in range(last_end, len(text)):
        out_chars.append(text[j])
        out_origins.append(base_map.entries[j])
    return "".join(out_chars), SpanMap(out_origins, orig_len=base_map._orig_len), changed


# --------------------------------------------------------------------------
# Detector entry point
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationConfig:
    """Tunable knobs for `NormalizationDetector`.

    `recursion_cap` bounds how many times we re-run the decoding
    chain when an inner step exposes new encoded content (e.g. a
    base64 string that decodes into URL-encoded data). The default
    of 3 matches the convention in Purview's content extractor and
    is sufficient for real-world inputs while bounding cost.
    """

    enable_nfkc: bool = True
    enable_strip_ignorable: bool = True
    enable_html_entities: bool = True
    enable_url_decode: bool = True
    enable_base64: bool = True
    recursion_cap: int = 3


class NormalizationDetector:
    """Pre-detection canonicalization layer.

    `name` is "normalizer". This is not a `DetectorAdapter` subclass
    because it does not produce `Detection` objects; it produces a
    `NormalizationResult` consumed by `DetectionPipeline` ahead of
    the regex / OPF / Presidio fan-out.
    """

    name = "normalizer"

    def __init__(self, config: NormalizationConfig | None = None) -> None:
        self._config = config or NormalizationConfig()

    def normalize(self, text: str) -> NormalizationResult:
        """Run the canonicalization chain on `text`.

        Order of operations:
          1. NFKC compatibility canonicalization (Unicode TR #15).
          2. Strip default-ignorable code points (UAX #44).
          3. HTML entity decode.
          4. URL percent-decode.
          5. Base64 nested-content decode.

        Steps 3-5 are run inside a recursion loop bounded by
        `recursion_cap`: if any of them changed the text, we re-run
        the chain on the new text so a base64-encoded URL-encoded
        payload (or vice versa) gets fully unwrapped.
        """
        cfg = self._config
        flags: list[str] = []
        normalized = text
        span_map = SpanMap.identity(text)

        if cfg.enable_nfkc:
            normalized, span_map, changed = _apply_nfkc(normalized, span_map)
            if changed:
                flags.append("nfkc")

        if cfg.enable_strip_ignorable:
            before = normalized
            normalized, span_map = _strip_default_ignorable(normalized, span_map)
            if normalized != before:
                flags.append("default_ignorable")

        for _ in range(max(1, cfg.recursion_cap)):
            any_changed = False
            if cfg.enable_html_entities:
                normalized, span_map, changed = _decode_html_entities(normalized, span_map)
                if changed:
                    any_changed = True
                    if "html_entity" not in flags:
                        flags.append("html_entity")
            if cfg.enable_url_decode:
                normalized, span_map, changed = _decode_url(normalized, span_map)
                if changed:
                    any_changed = True
                    if "url_encoded" not in flags:
                        flags.append("url_encoded")
            if cfg.enable_base64:
                normalized, span_map, changed = _decode_nested_base64(normalized, span_map)
                if changed:
                    any_changed = True
                    if "base64_nested" not in flags:
                        flags.append("base64_nested")
            if not any_changed:
                break

        return NormalizationResult(
            original=text,
            normalized=normalized,
            span_map=span_map,
            flags=tuple(flags),
        )


# Re-export `compose` so tests and callers in the same package can
# import it from this detector module if they need to compose maps
# manually. Kept thin to preserve the canonical home in
# `core.normalization`.
__all__ = [
    "NormalizationDetector",
    "NormalizationConfig",
    "compose",
]
