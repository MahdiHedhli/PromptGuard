"""DetectorUnavailableError surfaces when OPF is enabled but unreachable."""

from __future__ import annotations

import httpx
import pytest
import respx

from promptguard.core.pipeline_factory import (
    DetectorUnavailableError,
    build_pipeline_from_policy,
)
from promptguard.core.policy import (
    DetectorConfig,
    DetectorToggle,
    Policy,
)


def _policy_with_opf(enabled: bool) -> Policy:
    return Policy(
        name="t",
        detectors=DetectorConfig(
            regex=DetectorToggle(enabled=False),
            opf=DetectorToggle(enabled=enabled),
            presidio=DetectorToggle(enabled=False),
            llm_judge=DetectorToggle(enabled=False),
        ),
    )


@respx.mock
def test_pipeline_factory_opf_unreachable_raises_with_actionable_message() -> None:
    respx.get("http://opf.test/ready").mock(
        return_value=httpx.Response(503, json={"status": "loading"})
    )
    with pytest.raises(DetectorUnavailableError) as exc_info:
        build_pipeline_from_policy(_policy_with_opf(True), opf_url="http://opf.test")
    msg = str(exc_info.value)
    assert "OPF model not available" in msg
    assert "Refusing to start pipeline" in msg
    assert "detectors.opf.enabled = false" in msg
    assert "http://opf.test" in msg


@respx.mock
def test_pipeline_factory_opf_ready_proceeds() -> None:
    respx.get("http://opf.test/ready").mock(return_value=httpx.Response(200))
    pipeline = build_pipeline_from_policy(
        _policy_with_opf(True), opf_url="http://opf.test"
    )
    names = [d.name for d in pipeline.detectors]
    assert "opf" in names


def test_pipeline_factory_opf_disabled_does_not_probe_service() -> None:
    """If OPF is disabled in policy, we must not network out to /ready."""
    policy = Policy(
        name="t",
        detectors=DetectorConfig(
            regex=DetectorToggle(enabled=True),
            opf=DetectorToggle(enabled=False),
            presidio=DetectorToggle(enabled=False),
            llm_judge=DetectorToggle(enabled=False),
        ),
    )
    # respx not used: any network attempt would fail since opf.test isn't real.
    pipeline = build_pipeline_from_policy(policy, opf_url="http://opf.test")
    assert "opf" not in [d.name for d in pipeline.detectors]
    assert "regex" in [d.name for d in pipeline.detectors]


def test_pipeline_factory_zero_detectors_raises() -> None:
    policy = Policy(
        name="t",
        detectors=DetectorConfig(
            regex=DetectorToggle(enabled=False),
            opf=DetectorToggle(enabled=False),
            presidio=DetectorToggle(enabled=False),
            llm_judge=DetectorToggle(enabled=False),
        ),
    )
    with pytest.raises(DetectorUnavailableError) as exc_info:
        build_pipeline_from_policy(policy, skip_opf_readiness_check=True)
    assert "zero detectors" in str(exc_info.value).lower()


def test_pipeline_factory_llm_judge_enabled_raises_v1() -> None:
    policy = Policy(
        name="t",
        detectors=DetectorConfig(
            regex=DetectorToggle(enabled=True),
            opf=DetectorToggle(enabled=False),
            presidio=DetectorToggle(enabled=False),
            llm_judge=DetectorToggle(enabled=True),
        ),
    )
    with pytest.raises(DetectorUnavailableError) as exc_info:
        build_pipeline_from_policy(policy, skip_opf_readiness_check=True)
    assert "LLM judge" in str(exc_info.value)
    assert "v1.1" in str(exc_info.value)
