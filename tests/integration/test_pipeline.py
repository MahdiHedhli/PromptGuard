"""End-to-end integration: prompt -> DetectionPipeline -> ActionEngine.

OPF and Presidio are HTTP-backed and not available in unit-test runs.
This test exercises the pipeline-with-RegexDetector path that ships in v1
and validates that the detection layer is wired and the action engine
makes the right call against a synthetic PII prompt. The OPF/Presidio
HTTP paths are exercised separately under the `docker` marker.
"""

from __future__ import annotations

import pytest

from promptguard.actions import ActionContext, ActionEngine
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Category
from promptguard.detectors.regex_detector import RegexDetector
from promptguard.policies.local_yaml import LocalYAMLPolicy


@pytest.mark.integration
async def test_prompt_with_pii_routed_through_pipeline(
    synthetic_pii_prompt: str,
    policies_dir,
) -> None:
    pipeline = DetectionPipeline([RegexDetector()])
    policy = LocalYAMLPolicy(policies_dir / "default.yaml").load()
    engine = ActionEngine(policy)

    detections = await pipeline.detect_all(synthetic_pii_prompt)
    result = engine.apply(
        synthetic_pii_prompt,
        detections,
        ActionContext(conversation_id="conv-it-1", request_id="req-it-1"),
    )

    cats = {d.category for d in detections}
    # The synthetic prompt contains DB URL, JWT, AWS key, internal IP, email, domain.
    assert {
        Category.DATABASE_URL,
        Category.JWT,
        Category.CLOUD_API_KEY,
        Category.INTERNAL_IP,
        Category.EMAIL,
    }.issubset(cats), f"missing expected categories, got {cats}"

    # Default policy BLOCKs DB URL / JWT / cloud key, so the request must be blocked.
    assert result.blocked, f"expected block; violations={result.violations}"
    blocked_categories = {v.category for v in result.violations}
    assert "database_url" in blocked_categories
    assert "jwt" in blocked_categories
    assert "cloud_api_key" in blocked_categories
    # Block does not rewrite the text.
    assert result.rewritten_text == synthetic_pii_prompt


@pytest.mark.integration
async def test_clean_prompt_passes_through(
    synthetic_clean_prompt: str,
    policies_dir,
) -> None:
    pipeline = DetectionPipeline([RegexDetector()])
    policy = LocalYAMLPolicy(policies_dir / "default.yaml").load()
    engine = ActionEngine(policy)

    detections = await pipeline.detect_all(synthetic_clean_prompt)
    result = engine.apply(
        synthetic_clean_prompt,
        detections,
        ActionContext(conversation_id="conv-it-2", request_id="req-it-2"),
    )

    assert not result.blocked
    assert result.rewritten_text == synthetic_clean_prompt
    # No high-severity categories in clean prose.
    forbidden = {
        Category.PRIVATE_KEY,
        Category.CLOUD_API_KEY,
        Category.DATABASE_URL,
        Category.JWT,
        Category.SECRET,
    }
    assert not any(d.category in forbidden for d in detections)


@pytest.mark.integration
async def test_pipeline_isolates_detector_failures() -> None:
    """A misbehaving detector must not abort the pipeline."""

    class _Boom:
        name = "boom"

        async def detect(self, _text: str):
            raise RuntimeError("detector imploded")

    pipeline = DetectionPipeline([RegexDetector(), _Boom()])
    results = await pipeline.run("user@example.com")
    by_name = {r.detector: r for r in results}
    assert by_name["boom"].error is not None
    assert "RuntimeError" in by_name["boom"].error
    # Regex still produced its email detection.
    regex_dets = by_name["regex"].detections
    assert any(d.category == Category.EMAIL for d in regex_dets)
