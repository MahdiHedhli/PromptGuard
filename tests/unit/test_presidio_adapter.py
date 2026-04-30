"""PresidioDetector unit test against a mocked HTTP service via respx."""

from __future__ import annotations

import httpx
import respx

from promptguard.core.policy import Category
from promptguard.detectors.presidio import PresidioDetector


@respx.mock
async def test_presidio_parses_list_response_and_maps_entities() -> None:
    respx.post("http://presidio.test/analyze").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 13, "score": 0.95, "text": "x@example.com"},
                {"entity_type": "PERSON", "start": 14, "end": 22, "score": 0.85, "text": "Jane Doe"},
                {"entity_type": "UNKNOWN_TYPE", "start": 30, "end": 35, "score": 0.6, "text": "stuff"},
            ],
        )
    )
    detector = PresidioDetector(base_url="http://presidio.test")
    detections = await detector.detect("any text")
    await detector.aclose()
    cats = {d.category for d in detections}
    assert Category.EMAIL in cats
    assert Category.PRIVATE_NAME in cats
    assert Category.OTHER in cats
