"""Detection primitives and the DetectionPipeline orchestrator.

A `Detector` takes raw text and returns a list of `Detection` spans.
A `DetectionPipeline` fans out to every configured detector, runs them
concurrently, and aggregates their outputs.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Protocol

from promptguard.core.policy import Category


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

    def __init__(self, detectors: list[Detector]) -> None:
        if not detectors:
            raise ValueError("DetectionPipeline requires at least one detector")
        self._detectors = detectors

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    async def run(self, text: str) -> list[DetectorResult]:
        async def _one(detector: Detector) -> DetectorResult:
            try:
                detections = await detector.detect(text)
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
