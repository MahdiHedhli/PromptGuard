"""Stage-1 regex detector.

Catches structured / deterministic data shapes: keys, JWTs, IPs, DB URLs.
Per the multi-stage layering decision (research-notes section 6), this is
the deterministic floor: anything matched here is reported regardless of
what later stages do.
"""

from __future__ import annotations

from collections.abc import Iterable

from promptguard.core.detection import Detection
from promptguard.core.policy import Category
from promptguard.detectors.regex_patterns import PATTERNS, PatternSpec


class RegexDetector:
    name: str = "regex"

    def __init__(self, patterns: Iterable[PatternSpec] | None = None) -> None:
        self._patterns = tuple(patterns) if patterns is not None else PATTERNS

    @property
    def patterns(self) -> tuple[PatternSpec, ...]:
        return self._patterns

    def detect_sync(self, text: str) -> list[Detection]:
        out: list[Detection] = []
        for spec in self._patterns:
            for match in spec.pattern.finditer(text):
                out.append(
                    Detection(
                        category=spec.category,
                        start=match.start(),
                        end=match.end(),
                        matched_text=match.group(0),
                        confidence=spec.confidence,
                        detector=f"{self.name}:{spec.name}",
                    )
                )
        return _dedupe_overlapping(out)

    async def detect(self, text: str) -> list[Detection]:
        # Regex is fast enough that running on the event loop thread is fine
        # at v1 sizes. If we ever benchmark prompts > ~100KB, move to a
        # thread executor; the work is GIL-friendly.
        return self.detect_sync(text)


def _dedupe_overlapping(detections: list[Detection]) -> list[Detection]:
    """When two patterns match overlapping spans for the same category,
    keep the longer / higher-confidence one. Different categories on the
    same span are kept (a JWT is also a "secret").
    """
    if not detections:
        return detections
    by_category: dict[Category, list[Detection]] = {}
    for d in detections:
        by_category.setdefault(d.category, []).append(d)
    kept: list[Detection] = []
    for cat_detections in by_category.values():
        cat_detections.sort(key=lambda d: (d.start, -(d.end - d.start), -d.confidence))
        last_end = -1
        for d in cat_detections:
            if d.start >= last_end:
                kept.append(d)
                last_end = d.end
    kept.sort(key=lambda d: (d.start, d.end))
    return kept
