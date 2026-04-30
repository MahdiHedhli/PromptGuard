"""PromptGuard: local LLM proxy that prevents PII and sensitive data from leaving the host."""

from promptguard.core.detection import Detection, DetectionPipeline, DetectorResult
from promptguard.core.policy import Action, Category, Policy, PolicyRule

__version__ = "0.1.0a1"

__all__ = [
    "Action",
    "Category",
    "Detection",
    "DetectionPipeline",
    "DetectorResult",
    "Policy",
    "PolicyRule",
    "__version__",
]
