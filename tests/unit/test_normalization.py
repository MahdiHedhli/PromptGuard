"""Tests for the input-canonicalization layer.

Each sanitization step has a positive test (input is changed in the
expected way), an idempotency test (re-running on already-canonical
text is a no-op), and a span-map test (a detection in normalized text
remaps back to the right original-text region).

Test fixtures use clearly-fake credential-shaped strings like
`AKIAFAKE_FAKE_FAKE_FAKE` so the test data is unambiguously synthetic.
"""

from __future__ import annotations

import asyncio
import base64
import random
from dataclasses import dataclass
from typing import ClassVar

import pytest

from promptguard.core.detection import Detection, DetectionPipeline
from promptguard.core.normalization import SpanMap
from promptguard.core.policy import Category
from promptguard.detectors.base import DetectorAdapter
from promptguard.detectors.normalizer import NormalizationDetector


# ---------------------------------------------------------------------------
# Per-step positive tests
# ---------------------------------------------------------------------------


def test_clean_input_is_identity() -> None:
    n = NormalizationDetector()
    r = n.normalize("hello world, no obfuscation here")
    assert r.normalized == r.original
    assert not r.changed
    assert r.flags == ()


def test_default_ignorable_codepoints_are_stripped() -> None:
    n = NormalizationDetector()
    # Insert ZWSP, ZWNJ, ZWJ, BOM into a credential-shaped fake.
    text = "A​K‌I‍A" + "﻿" + "FAKE_FAKE_FAKE_FAKE"
    r = n.normalize(text)
    assert r.normalized == "AKIAFAKE_FAKE_FAKE_FAKE"
    assert "default_ignorable" in r.flags


def test_nfkc_folds_fullwidth_letters() -> None:
    n = NormalizationDetector()
    r = n.normalize("ＡＢＣ123")
    assert r.normalized == "ABC123"
    assert "nfkc" in r.flags


def test_nfkc_idempotent_on_canonical_input() -> None:
    n = NormalizationDetector()
    r1 = n.normalize("ABC123")
    r2 = n.normalize(r1.normalized)
    assert r2.normalized == r1.normalized
    assert "nfkc" not in r2.flags


def test_html_entities_decoded() -> None:
    n = NormalizationDetector()
    r = n.normalize("&#x41;KIAFAKE_FAKE_FAKE")
    assert r.normalized == "AKIAFAKE_FAKE_FAKE"
    assert "html_entity" in r.flags


def test_url_percent_decoded() -> None:
    n = NormalizationDetector()
    r = n.normalize("hello %41KIAFAKE world")
    assert r.normalized == "hello AKIAFAKE world"
    assert "url_encoded" in r.flags


def test_base64_nested_content_decoded() -> None:
    n = NormalizationDetector()
    inner = "AKIAFAKE_FAKE_FAKE_FAKE"
    payload = base64.b64encode(inner.encode()).decode()
    r = n.normalize("see token: " + payload)
    assert inner in r.normalized
    assert "base64_nested" in r.flags


def test_base64_recursion_unwraps_double_wrap() -> None:
    n = NormalizationDetector()
    # base64(base64(payload)). Recursion cap is 3, so 2 levels work.
    inner = "AKIAFAKE_FAKE_FAKE_FAKE"
    once = base64.b64encode(inner.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()
    r = n.normalize("nested: " + twice)
    assert inner in r.normalized


def test_base64_skips_non_printable_decode() -> None:
    """Random binary bytes that happen to base64-encode shouldn't get decoded
    into the normalized text. The printable-content gate filters them out."""
    n = NormalizationDetector()
    rnd = random.Random(0)
    binary = bytes(rnd.randrange(0, 256) for _ in range(64))
    payload = base64.b64encode(binary).decode()
    r = n.normalize("see token: " + payload)
    # Encoded form should still be present (not replaced).
    assert payload in r.normalized
    assert "base64_nested" not in r.flags


def test_url_encoded_inside_base64_unwraps_to_payload() -> None:
    """Recursion: a URL-encoded string wrapped in base64 unwraps fully."""
    n = NormalizationDetector()
    inner = "AKIAFAKE_FAKE_FAKE_FAKE"
    url_encoded = "%41" + inner[1:]
    payload = base64.b64encode(url_encoded.encode()).decode()
    r = n.normalize("see: " + payload)
    assert inner in r.normalized


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "AKIAFAKE_FAKE_FAKE_FAKE",
        "hello world",
        "no obfuscation, plain ASCII text.",
        "alice@example.com is a synthetic email",
    ],
)
def test_idempotent_on_canonical_inputs(raw: str) -> None:
    n = NormalizationDetector()
    r1 = n.normalize(raw)
    r2 = n.normalize(r1.normalized)
    assert r2.normalized == r1.normalized
    assert not r2.changed


# ---------------------------------------------------------------------------
# Span map correctness
# ---------------------------------------------------------------------------


def test_span_map_zero_width_run_maps_to_full_original_range() -> None:
    n = NormalizationDetector()
    text = "A​K‌I‍AFAKE"
    r = n.normalize(text)
    assert r.normalized == "AKIAFAKE"
    # span [0,4) in normalized = "AKIA". Should map to [0,7) in original
    # (the four real chars plus the three zero-widths between them).
    s, e = r.span_map.to_original(0, 4)
    assert (s, e) == (0, 7)
    assert text[s:e] == "A​K‌I‍A"


def test_span_map_decoded_chunk_maps_to_full_original_chunk() -> None:
    n = NormalizationDetector()
    inner = "AKIAFAKE_FAKE_FAKE_FAKE"
    payload = base64.b64encode(inner.encode()).decode()
    prefix = "see "
    text = prefix + payload
    r = n.normalize(text)
    assert inner in r.normalized
    # Find where in normalized the decoded payload lives, then map.
    start_norm = r.normalized.index(inner)
    end_norm = start_norm + len(inner)
    s, e = r.span_map.to_original(start_norm, end_norm)
    # The full original range covering the entire base64 string.
    assert text[s:e] == payload


def test_span_map_url_encoded_run_maps_to_encoded_form() -> None:
    n = NormalizationDetector()
    text = "key=%41KIAFAKE"
    r = n.normalize(text)
    assert "AKIAFAKE" in r.normalized
    # Map the position of "AKIAFAKE" in normalized back to original.
    s_norm = r.normalized.index("AKIAFAKE")
    e_norm = s_norm + len("AKIAFAKE")
    s, e = r.span_map.to_original(s_norm, e_norm)
    # Should cover the percent-encoded "%41" and the trailing "KIAFAKE"
    assert text[s:e].startswith("%41")
    assert text[s:e].endswith("KIAFAKE")


def test_span_map_html_entity_run_maps_to_entity_form() -> None:
    n = NormalizationDetector()
    text = "&#x41;KIAFAKE_FAKE"
    r = n.normalize(text)
    assert "AKIAFAKE_FAKE" in r.normalized
    s_norm = r.normalized.index("AKIAFAKE_FAKE")
    e_norm = s_norm + len("AKIAFAKE_FAKE")
    s, e = r.span_map.to_original(s_norm, e_norm)
    assert text[s:e].startswith("&#x41;")


def test_span_map_identity_within_kept_runs() -> None:
    n = NormalizationDetector()
    text = "hello A​KIAFAKE world"
    r = n.normalize(text)
    # "hello " is identity; first 6 chars of normalized correspond
    # to first 6 of original.
    s, e = r.span_map.to_original(0, 6)
    assert (s, e) == (0, 6)
    assert text[s:e] == "hello "


# ---------------------------------------------------------------------------
# Span map fuzz: arbitrary spans round-trip into the original text
# ---------------------------------------------------------------------------


def test_span_map_fuzz_random_inputs_remap_to_valid_original_ranges() -> None:
    """For a corpus of randomly-built mixed-obfuscation inputs, every
    span we ask the map to project must come back as a valid half-open
    range within the original text and must not exceed the original
    length. Asserts the structural invariant of the span map.
    """
    rng = random.Random(20260502)
    pieces = [
        "alice@example.com",
        "AKIAFAKE_FAKE_FAKE_FAKE",
        "10.0.13.42",
        "regular prose ",
        "more text here",
    ]
    obfuscators = [
        lambda s: s,  # identity
        lambda s: "​".join(s),  # zero-width injection
        lambda s: base64.b64encode(s.encode()).decode(),
        lambda s: "".join(f"%{ord(c):02X}" if c.isalnum() else c for c in s),
        lambda s: "".join(f"&#x{ord(c):02x};" if c.isalnum() else c for c in s),
    ]
    n = NormalizationDetector()
    for trial in range(200):
        parts = [
            obfuscators[rng.randrange(len(obfuscators))](
                pieces[rng.randrange(len(pieces))]
            )
            for _ in range(rng.randrange(1, 4))
        ]
        text = " ".join(parts)
        r = n.normalize(text)
        # Every span in normalized must remap to a valid range.
        norm_len = len(r.normalized)
        for _ in range(5):
            a = rng.randrange(0, norm_len + 1)
            b = rng.randrange(a, norm_len + 1)
            s, e = r.span_map.to_original(a, b)
            assert 0 <= s <= e <= len(text), f"trial {trial}: bad range ({s},{e}) for orig len {len(text)}"


def test_span_map_full_range_covers_full_original() -> None:
    n = NormalizationDetector()
    text = "A​K‌I‍AFAKE plus tail"
    r = n.normalize(text)
    s, e = r.span_map.to_original(0, len(r.normalized))
    assert (s, e) == (0, len(text))


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


@dataclass
class _MarkerDetector(DetectorAdapter):
    """Test detector that flags every occurrence of a literal marker."""

    name: ClassVar[str] = "marker"
    marker: str = "AKIAFAKE_FAKE_FAKE_FAKE"

    async def detect(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        i = 0
        while True:
            j = text.find(self.marker, i)
            if j < 0:
                break
            out.append(
                Detection(
                    category=Category.CLOUD_API_KEY,
                    start=j,
                    end=j + len(self.marker),
                    matched_text=text[j : j + len(self.marker)],
                    confidence=1.0,
                    detector=self.name,
                )
            )
            i = j + 1
        return out


def test_pipeline_without_normalizer_misses_zero_width_injected_marker() -> None:
    """Establishes the gap. With no normalizer, a zero-width-injected
    marker is invisible to the literal-match detector."""
    det = _MarkerDetector()
    text = "leak: A​K‌I‍AFAKE_FAKE_FAKE_FAKE today"
    pipeline = DetectionPipeline([det])
    detections = asyncio.run(pipeline.detect_all(text))
    assert detections == []


def test_pipeline_with_normalizer_catches_zero_width_injected_marker() -> None:
    """Closes the gap. The same input is canonicalized, then matched,
    and the reported span maps back to the obfuscated original range."""
    det = _MarkerDetector()
    text = "leak: A​K‌I‍AFAKE_FAKE_FAKE_FAKE today"
    pipeline = DetectionPipeline([det], normalizer=NormalizationDetector())
    detections = asyncio.run(pipeline.detect_all(text))
    assert len(detections) == 1
    d = detections[0]
    # The reported span must reference original text, not normalized.
    assert text[d.start : d.end].replace("​", "").replace(
        "‌", ""
    ).replace("‍", "") == "AKIAFAKE_FAKE_FAKE_FAKE"
    assert d.matched_text == text[d.start : d.end]


def test_pipeline_with_normalizer_catches_base64_wrapped_marker() -> None:
    det = _MarkerDetector()
    inner = "AKIAFAKE_FAKE_FAKE_FAKE"
    payload = base64.b64encode(inner.encode()).decode()
    text = f"see {payload} please"
    pipeline = DetectionPipeline([det], normalizer=NormalizationDetector())
    detections = asyncio.run(pipeline.detect_all(text))
    assert len(detections) == 1
    d = detections[0]
    # Original-text span covers the entire base64 chunk.
    assert text[d.start : d.end] == payload


def test_pipeline_normalizer_off_when_input_clean() -> None:
    """When normalization made no changes, span map is bypassed and
    detector spans pass through unchanged."""
    det = _MarkerDetector()
    text = "leak: AKIAFAKE_FAKE_FAKE_FAKE today"
    pipeline = DetectionPipeline([det], normalizer=NormalizationDetector())
    detections = asyncio.run(pipeline.detect_all(text))
    assert len(detections) == 1
    d = detections[0]
    assert text[d.start : d.end] == "AKIAFAKE_FAKE_FAKE_FAKE"
    # Confirm the offsets equal the literal find result.
    assert d.start == text.index("AKIAFAKE_FAKE_FAKE_FAKE")
