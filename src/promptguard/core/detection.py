"""Detection primitives and the DetectionPipeline orchestrator.

A `Detector` takes raw text and returns a list of `Detection` spans.
A `DetectionPipeline` fans out to every configured detector, runs them
concurrently, and aggregates their outputs.

If a `NormalizationDetector` is configured, the pipeline canonicalizes
the input first (Unicode NFKC, default-ignorable stripping, HTML /
URL / base64 decoding) and runs every downstream detector against
the canonical form. Reported spans are remapped back to the original
input via the normalization span map so the rewrite path can
substitute the user-visible text.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from promptguard.core.policy import Category

if TYPE_CHECKING:
    from promptguard.detectors.normalizer import NormalizationDetector


@dataclass(frozen=True, slots=True)
class Detection:
    """A single detected span.

    `start` and `end` are character offsets, half-open: text[start:end].
    `confidence` is in [0.0, 1.0]; deterministic detectors (regex) report 1.0.
    """

    category: Category
    start: int
    end: int
    matched_text: str
    confidence: float
    detector: str


@dataclass(frozen=True, slots=True)
class DetectorResult:
    detector: str
    detections: tuple[Detection, ...]
    error: str | None = None


class Detector(Protocol):
    """Minimal detector contract.

    Adapters that wrap remote services (OPF, Presidio) should be async.
    Synchronous adapters (regex) can implement `detect` directly; the pipeline
    will run them in a worker thread to avoid blocking the event loop.
    """

    name: str

    async def detect(self, text: str) -> list[Detection]: ...


class DetectionPipeline:
    """Run multiple detectors over a payload and merge their outputs.

    Detectors are run concurrently. Failures in one detector do not abort
    the pipeline: they are reported as `DetectorResult.error` so the caller
    can decide whether to fail-closed or fail-open per policy.
    """

    def __init__(
        self,
        detectors: list[Detector],
        normalizer: "NormalizationDetector | None" = None,
    ) -> None:
        if not detectors:
            raise ValueError("DetectionPipeline requires at least one detector")
        self._detectors = detectors
        self._normalizer = normalizer

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    @property
    def normalizer(self) -> "NormalizationDetector | None":
        return self._normalizer

    async def run(self, text: str) -> list[DetectorResult]:
        scan_text, span_map = self._prepare(text)

        async def _one(detector: Detector) -> DetectorResult:
            try:
                detections = await detector.detect(scan_text)
                if span_map is not None:
                    detections = [self._remap(d, scan_text, text, span_map) for d in detections]
                return DetectorResult(
                    detector=detector.name,
                    detections=tuple(detections),
                )
            except Exception as exc:
                return DetectorResult(
                    detector=detector.name,
                    detections=(),
                    error=f"{type(exc).__name__}: {exc}",
                )

        return list(await asyncio.gather(*(_one(d) for d in self._detectors)))

    async def detect_all(self, text: str) -> list[Detection]:
        """Convenience: flatten successful detections from every detector."""
        results = await self.run(text)
        out: list[Detection] = []
        for result in results:
            out.extend(result.detections)
        return out

    def _prepare(self, text: str):  # type: ignore[no-untyped-def]
        """Run the normalizer if configured.

        Returns the text every detector should scan plus the span map
        that lets us project back to the original. When normalization
        is off (or made no changes), `span_map` is None and detectors
        scan the original text directly with no remapping cost.
        """
        if self._normalizer is None:
            return text, None
        result = self._normalizer.normalize(text)
        if not result.changed:
            return text, None
        return result.normalized, result.span_map

    @staticmethod
    def _remap(detection: Detection, scan_text: str, orig_text: str, span_map) -> Detection:  # type: ignore[no-untyped-def]
        orig_start, orig_end = span_map.to_original(detection.start, detection.end)
        return replace(
            detection,
            start=orig_start,
            end=orig_end,
            matched_text=orig_text[orig_start:orig_end],
        )
