"""DetectorAdapter contract.

All detectors share one interface so the `DetectionPipeline` can fan out
to them uniformly. This module formalizes that contract as an abstract
base. v1 adapters (`RegexDetector`, `OPFDetector`, `PresidioDetector`)
all conform.

# Contract

A `DetectorAdapter` produces zero or more `Detection` spans for a given
input text. The contract has four binding rules:

1. **Span-based output.** Every reported finding is a `Detection` with
   half-open `[start, end)` character offsets into the input text and
   a `Category`. The `matched_text` field MUST equal `text[start:end]`
   verbatim, including capitalization and whitespace.

2. **Category mapping discipline.** Every finding maps to one of the
   `Category` enum values in `promptguard.core.policy.Category`. If a
   detector emits a label that does not map cleanly, it must use
   `Category.OTHER` so the action engine can still log the finding.
   Adapters that wrap a third-party detector (Presidio, OPF) document
   their label-to-category mapping inline; tests assert the mapping.

3. **Determinism (deterministic-ish).** For a given input, the same
   adapter must produce the same spans across calls within the same
   process. Adapters wrapping non-deterministic models (LLM judge) are
   permitted to drift but MUST set a deterministic seed where the model
   exposes one. Tests can pin the model to verify determinism.

4. **Failure isolation.** Adapters MAY raise on errors; the pipeline
   isolates exceptions per adapter so one detector failing does not
   prevent the others from running. An adapter that wants to log a
   warning and return zero detections (rather than raise) is also
   permitted, and is the right choice for transient remote failures.

# Optional methods

  - `aclose()`: async cleanup for adapters holding HTTP clients or
    long-lived connections. Called when the pipeline is torn down.

# Naming

The `name` attribute is the operator-facing label that appears in
audit logs and error envelopes (`detector` field on `Detection`).
Convention: lowercase, no spaces. Standard names: `regex`, `opf`,
`presidio`.

# Concurrency

Adapters are called concurrently by the pipeline (`asyncio.gather`).
An adapter that holds mutable state across calls (e.g. a TokenMap, a
cache) must guard it appropriately. The reference adapters are
stateless across calls aside from HTTP clients which are thread-safe.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from promptguard.core.detection import Detection


class DetectorAdapter(ABC):
    """Abstract base for all detectors.

    Concrete adapters set `name` as a class variable and implement
    `detect`. The base class provides default no-op `aclose` so adapters
    that do not hold resources do not have to override.
    """

    name: ClassVar[str] = "abstract"

    @abstractmethod
    async def detect(self, text: str) -> list[Detection]:
        """Return zero or more detections for `text`.

        Implementations MUST honor the contract documented at module
        level. Most importantly: `matched_text` for each returned
        detection equals `text[start:end]`; categories come from the
        `Category` enum; spans use half-open `[start, end)` semantics.
        """

    async def aclose(self) -> None:
        """Optional teardown hook. Default no-op."""
        return None
