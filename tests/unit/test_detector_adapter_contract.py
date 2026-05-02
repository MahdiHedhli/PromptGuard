"""DetectorAdapter contract conformance suite.

Every detector ships pinned to the ABC. This test sweeps the three
shipped adapters and asserts:

  * They subclass `DetectorAdapter`.
  * They expose a `name` class attribute (lowercase, no spaces).
  * `detect(text)` returns `list[Detection]`.
  * Each detection's `matched_text` equals `text[start:end]`.
  * Each detection's `category` is a `Category` enum member.
  * Determinism: same input twice yields the same span set.

OPF and Presidio are HTTP-backed; we mock them via respx so the test
runs without the docker stack.
"""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from promptguard.core.detection import Detection
from promptguard.core.policy import Category
from promptguard.detectors import (
    DetectorAdapter,
    OPFDetector,
    PresidioDetector,
    RegexDetector,
)


# ------------ subclass + name ------------------------------------


@pytest.mark.parametrize(
    "adapter_cls",
    [RegexDetector, OPFDetector, PresidioDetector],
)
def test_subclasses_detector_adapter(adapter_cls) -> None:
    assert issubclass(adapter_cls, DetectorAdapter)


@pytest.mark.parametrize(
    ("adapter_cls", "expected_name"),
    [
        (RegexDetector, "regex"),
        (OPFDetector, "opf"),
        (PresidioDetector, "presidio"),
    ],
)
def test_name_class_attribute(adapter_cls, expected_name: str) -> None:
    assert adapter_cls.name == expected_name
    assert adapter_cls.name.islower()
    assert " " not in adapter_cls.name


# ------------ detect signature ----------------------------------


@pytest.mark.parametrize(
    "adapter_cls",
    [RegexDetector, OPFDetector, PresidioDetector],
)
def test_detect_is_async(adapter_cls) -> None:
    assert inspect.iscoroutinefunction(adapter_cls.detect)


# ------------ matched_text and category invariants --------------


async def test_regex_matched_text_equals_substring() -> None:
    text = "Email me at noreply@example.com from 10.0.0.5 today."
    det = RegexDetector()
    detections = await det.detect(text)
    assert detections
    for d in detections:
        assert d.matched_text == text[d.start : d.end], (
            f"matched_text mismatch on {d.detector}: "
            f"{d.matched_text!r} != {text[d.start:d.end]!r}"
        )
        assert isinstance(d.category, Category)


async def test_regex_determinism() -> None:
    text = "Email me at noreply@example.com from 10.0.0.5 today."
    det = RegexDetector()
    a = await det.detect(text)
    b = await det.detect(text)
    assert [(d.category, d.start, d.end) for d in a] == [
        (d.category, d.start, d.end) for d in b
    ]


@respx.mock
async def test_opf_matched_text_equals_substring_via_mock() -> None:
    text = "alice@example.com"
    respx.post("http://opf.test/detect").mock(
        return_value=httpx.Response(
            200,
            json={
                "detections": [
                    {"label": "private_email", "start": 0, "end": 17, "score": 0.97, "text": "alice@example.com"},
                ]
            },
        )
    )
    det = OPFDetector(base_url="http://opf.test")
    detections = await det.detect(text)
    await det.aclose()
    assert detections[0].matched_text == text[detections[0].start : detections[0].end]
    assert isinstance(detections[0].category, Category)


@respx.mock
async def test_presidio_matched_text_equals_substring_via_mock() -> None:
    text = "alice@example.com"
    respx.post("http://presidio.test/analyze").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 17, "score": 0.95, "text": "alice@example.com"},
            ],
        )
    )
    det = PresidioDetector(base_url="http://presidio.test")
    detections = await det.detect(text)
    await det.aclose()
    assert detections[0].matched_text == text[detections[0].start : detections[0].end]
    assert isinstance(detections[0].category, Category)


# ------------ unknown labels map to OTHER ----------------------


@respx.mock
async def test_opf_unknown_label_maps_to_other() -> None:
    respx.post("http://opf.test/detect").mock(
        return_value=httpx.Response(
            200,
            json={
                "detections": [
                    {"label": "novel_category", "start": 0, "end": 5, "score": 0.5, "text": "hello"},
                ]
            },
        )
    )
    det = OPFDetector(base_url="http://opf.test")
    detections = await det.detect("hello")
    await det.aclose()
    assert detections[0].category == Category.OTHER


@respx.mock
async def test_presidio_unknown_label_maps_to_other() -> None:
    respx.post("http://presidio.test/analyze").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"entity_type": "MEDICAL_LICENSE", "start": 0, "end": 5, "score": 0.7, "text": "hello"},
            ],
        )
    )
    det = PresidioDetector(base_url="http://presidio.test")
    detections = await det.detect("hello")
    await det.aclose()
    assert detections[0].category == Category.OTHER


# ------------ aclose default and overrides --------------------


def test_aclose_default_no_op_on_base() -> None:
    """The base ABC provides a default no-op aclose."""

    class _Probe(DetectorAdapter):
        name = "probe"

        async def detect(self, text):
            return []

    p = _Probe()
    import asyncio

    asyncio.run(p.aclose())  # must not raise


# ------------ Detection produced by every adapter conforms ----


def test_detection_dataclass_invariants() -> None:
    """Sanity check on the Detection shape."""
    d = Detection(
        category=Category.EMAIL,
        start=0,
        end=10,
        matched_text="x" * 10,
        confidence=0.9,
        detector="regex:test",
    )
    assert d.start <= d.end
    assert 0.0 <= d.confidence <= 1.0
    assert d.detector
