"""Build a `DetectionPipeline` from a `Policy` with hard-fail OPF readiness.

Mahdi's directive (Day 2): if a policy enables OPF and the OPF service is
unavailable, refuse to start the pipeline. PromptGuard's promise is that
PII never leaves the host; silently degrading to "OPF disabled" would
break that promise without operator awareness.

The exact error string is the one specified in the Day-2 brief.
"""

from __future__ import annotations

import os

import httpx

from promptguard.core.detection import DetectionPipeline, Detector
from promptguard.core.policy import Policy
from promptguard.detectors.opf import OPFDetector
from promptguard.detectors.presidio import PresidioDetector
from promptguard.detectors.regex_detector import RegexDetector


class DetectorUnavailableError(RuntimeError):
    """A detector required by policy could not be reached or initialized."""


def _opf_ready(base_url: str, timeout_s: float) -> tuple[bool, str]:
    """Probe the OPF service's /ready endpoint.

    Returns (ready, detail). `ready` is True iff the service responded 200.
    `detail` is operator-readable; passed verbatim into the error message
    when we hard-fail.
    """
    url = base_url.rstrip("/") + "/ready"
    try:
        resp = httpx.get(url, timeout=timeout_s)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
        return False, f"unreachable at {base_url} ({type(exc).__name__})"
    except httpx.RemoteProtocolError as exc:
        return False, f"protocol error from {base_url}: {exc!r}"
    if resp.status_code == 200:
        return True, ""
    # /ready returns 503 with a JSON detail when the model is still loading
    # or has failed to load. Surface whichever is more informative.
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    return False, f"{base_url} returned HTTP {resp.status_code}: {body!r}"


def build_pipeline_from_policy(
    policy: Policy,
    *,
    opf_url: str | None = None,
    presidio_url: str | None = None,
    opf_ready_timeout_s: float = 5.0,
    skip_opf_readiness_check: bool = False,
) -> DetectionPipeline:
    """Construct a DetectionPipeline whose detectors match the policy toggles.

    `skip_opf_readiness_check` is for unit tests that run without the
    container stack up; production callers should leave it False so the
    promise of "OPF really runs" is enforced.
    """
    opf_url = opf_url or os.environ.get("PROMPTGUARD_OPF_URL", "http://localhost:8081")
    presidio_url = presidio_url or os.environ.get(
        "PROMPTGUARD_PRESIDIO_URL", "http://localhost:5002"
    )

    detectors: list[Detector] = []

    if policy.detectors.regex.enabled:
        detectors.append(RegexDetector())

    if policy.detectors.opf.enabled:
        if not skip_opf_readiness_check:
            ready, detail = _opf_ready(opf_url, opf_ready_timeout_s)
            if not ready:
                raise DetectorUnavailableError(
                    f"OPF model not available at {opf_url}. "
                    f"Refusing to start pipeline. "
                    f"To run without OPF detection, set "
                    f"detectors.opf.enabled = false in your policy file. "
                    f"({detail})"
                )
        detectors.append(OPFDetector(base_url=opf_url))

    if policy.detectors.presidio.enabled:
        detectors.append(PresidioDetector(base_url=presidio_url))

    if policy.detectors.llm_judge.enabled:
        # The LLM judge is locked OFF in v1 (research-notes Decision 6).
        # If a policy enables it, fail loud rather than silently degrade.
        raise DetectorUnavailableError(
            "LLM judge is enabled in policy but the LLMJudgeDetector adapter "
            "ships in v1.1. Set detectors.llm_judge.enabled = false to start."
        )

    if not detectors:
        raise DetectorUnavailableError(
            "Policy enables zero detectors. At least one detector must be "
            "enabled, otherwise PromptGuard would forward all traffic unchecked."
        )

    return DetectionPipeline(detectors)
