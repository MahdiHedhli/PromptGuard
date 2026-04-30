"""End-to-end integration: prompt -> DetectionPipeline -> ActionEngine.

OPF and Presidio are HTTP-backed and not available in unit-test runs.
This test exercises the pipeline-with-RegexDetector path that ships in v1
and validates that the detection layer is wired and the action engine
makes the right call against a synthetic PII prompt. The OPF/Presidio
HTTP paths are exercised separately under the `docker` marker.
"""

from __future__ import annotations

import pytest

from promptguard.actions import ActionEngine
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Action, Category
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
    outcome = engine.decide(detections)

    cats = {d.category for d in detections}
    # The synthetic prompt contains DB URL, JWT, AWS key, internal IP, email, domain.
    assert {
        Category.DATABASE_URL,
        Category.JWT,
        Category.CLOUD_API_KEY,
        Category.INTERNAL_IP,
        Category.EMAIL,
    }.issubset(cats), f"missing expected categories, got {cats}"

    # Default policy BLOCKs DB URL / JWT / cloud key, so the outcome must be blocked.
    assert outcome.blocked, f"expected block; decisions={outcome.decisions}"

    actions_by_category: dict[Category, Action] = {}
    for d in outcome.decisions:
        actions_by_category.setdefault(d.detection.category, d.action)
    assert actions_by_category[Category.DATABASE_URL] == Action.BLOCK
    assert actions_by_category[Category.EMAIL] == Action.MASK
    assert actions_by_category[Category.INTERNAL_IP] == Action.TOKENIZE


@pytest.mark.integration
async def test_clean_prompt_passes_through(
    synthetic_clean_prompt: str,
    policies_dir,
) -> None:
    pipeline = DetectionPipeline([RegexDetector()])
    policy = LocalYAMLPolicy(policies_dir / "default.yaml").load()
    engine = ActionEngine(policy)

    detections = await pipeline.detect_all(synthetic_clean_prompt)
    outcome = engine.decide(detections)

    assert not outcome.blocked
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
