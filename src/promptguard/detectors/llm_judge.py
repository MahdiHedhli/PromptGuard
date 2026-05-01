"""Stage-4 LLM judge detector.

Locked OFF in v1 (research-notes Decision 6); skeleton wired here so the
adapter framework is observable in the codebase. Real implementation
lands Day 8 against Ollama as the reference local LLM. The Day-8 work
also wires the prompt template, JSON-output parsing with malformed-output
handling, and a configurable timeout.

Until Day 8, instantiating `LLMJudgeDetector` raises clearly. The
pipeline factory (`build_pipeline_from_policy`) refuses to start when
`detectors.llm_judge.enabled: true` regardless, so this guard is a
double-belt: even if the factory check is bypassed in a unit test, the
class itself cannot be silently used.
"""

from __future__ import annotations

import os
from typing import ClassVar

from promptguard.core.detection import Detection
from promptguard.detectors.base import DetectorAdapter

DEFAULT_OLLAMA_URL = os.environ.get("PROMPTGUARD_OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("PROMPTGUARD_LLM_JUDGE_MODEL", "llama3.1:8b-instruct-q4_K_M")
DEFAULT_TIMEOUT_S = float(os.environ.get("PROMPTGUARD_LLM_JUDGE_TIMEOUT_S", "2.0"))


class LLMJudgeNotImplemented(NotImplementedError):
    """Raised on instantiation until Day 8 wires the real implementation."""


class LLMJudgeDetector(DetectorAdapter):
    """Adapter skeleton for the optional LLM judge.

    v1 ships the class but not the implementation. The pipeline factory
    refuses to start when policy enables this detector; this constructor
    refuses to instantiate. Day 8 fills in:
      - Ollama HTTP client (httpx, async)
      - Structured prompt template (text in, JSON spans out)
      - Tolerant JSON parsing (parse failure -> no detection, log warn)
      - Configurable timeout (default 2s; on timeout return zero detections)
      - docs/llm-judge.md with FP/FN tendencies and model recommendations
    """

    name: ClassVar[str] = "llm_judge"

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        # Day 8 will replace this with a real implementation. Until then,
        # constructing one is a programming error: the policy schema gates
        # the feature off, and the pipeline factory enforces the gate.
        raise LLMJudgeNotImplemented(
            "LLMJudgeDetector is a v1 skeleton; real implementation lands Day 8. "
            "Set detectors.llm_judge.enabled = false in your policy file."
        )

    async def detect(self, text: str) -> list[Detection]:
        # Unreachable at v1 because __init__ raises. Kept for type-checkers
        # and so the abstract method is satisfied.
        return []
