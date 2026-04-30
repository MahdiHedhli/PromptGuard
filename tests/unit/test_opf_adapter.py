"""OPFDetector unit test against a mocked HTTP service via respx.

The actual OPF service runs in a container; this test validates label
mapping and parsing against the documented contract.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from promptguard.core.policy import Category
from promptguard.detectors.opf import OPFDetector


@respx.mock
async def test_opf_parses_response_and_maps_labels() -> None:
    respx.post("http://opf.test/detect").mock(
        return_value=httpx.Response(
            200,
            json={
                "detections": [
                    {"label": "private_email", "start": 5, "end": 22, "score": 0.97, "text": "x@e.com"},
                    {"label": "private_name", "start": 30, "end": 38, "score": 0.91, "text": "Jane Doe"},
                    {"label": "background", "start": 50, "end": 55, "score": 0.5, "text": "today"},
                ]
            },
        )
    )

    detector = OPFDetector(base_url="http://opf.test")
    detections = await detector.detect("any text")
    await detector.aclose()

    cats = {d.category for d in detections}
    assert Category.EMAIL in cats
    assert Category.PRIVATE_NAME in cats
    # background -> OTHER (visible but not in our actionable categories)
    assert Category.OTHER in cats


@respx.mock
async def test_opf_propagates_http_errors() -> None:
    respx.post("http://opf.test/detect").mock(return_value=httpx.Response(503))
    detector = OPFDetector(base_url="http://opf.test")
    with pytest.raises(httpx.HTTPStatusError):
        await detector.detect("x")
    await detector.aclose()
