"""Stage-4 LLM judge detector.

Default OFF (research-notes Decision 6). When operators enable it via
`detectors.llm_judge.enabled: true`, this adapter makes one HTTP call
per `detect()` to a local Ollama server and asks a small instruction-
tuned model to flag PII / secrets the deterministic stages may have
missed.

# Why this exists

Regex catches shapes; OPF catches context-aware PII; Presidio catches
org-specific entities. The LLM judge catches paraphrased and
adversarial cases the earlier stages do not see ("the user's address
is roughly downtown, near the train station", "their phone is roughly
nine fifty five, six two two, eighty seven thirty"). The judge is a
backstop, not a primary signal.

# Failure modes

The judge can be slow and the judge can be wrong. The adapter is
hardened against both:

  * Timeout (default 2s, configurable via `PROMPTGUARD_LLM_JUDGE_TIMEOUT_S`).
    On timeout return zero detections; do not fail the pipeline.
  * HTTP error (Ollama down, model not pulled). Return zero detections;
    log a warning. The pipeline keeps the regex / OPF / Presidio
    findings.
  * Malformed JSON output from the model. Return zero detections; log
    a warning. We do NOT trust the LLM to be syntactically correct
    every time; tolerant parsing is the only safe posture.

# Prompt template

Single-shot, structured. The model is asked to return JSON with a
specific shape. Non-conforming output is treated as zero findings,
which keeps the model's mistakes from corrupting the pipeline.

# Operator override

Operators can override the prompt template via
`PROMPTGUARD_LLM_JUDGE_PROMPT_PATH` pointing at a file with a Python
`str.format(...)` template that takes one positional argument
(`{0}` is the user text). docs/llm-judge.md documents the contract.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, ClassVar

import httpx

from promptguard.core.detection import Detection
from promptguard.core.policy import Category
from promptguard.detectors.base import DetectorAdapter

logger = logging.getLogger("promptguard.detectors.llm_judge")

DEFAULT_OLLAMA_URL = os.environ.get("PROMPTGUARD_OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("PROMPTGUARD_LLM_JUDGE_MODEL", "llama3.2:3b-instruct-q4_K_M")
DEFAULT_TIMEOUT_S = float(os.environ.get("PROMPTGUARD_LLM_JUDGE_TIMEOUT_S", "2.0"))
DEFAULT_PROMPT_PATH = os.environ.get("PROMPTGUARD_LLM_JUDGE_PROMPT_PATH", "")

# Default prompt. Operator can override via env var. The template is
# str.format()-style; argument {0} is the user text. The model is
# expected to return ONLY a JSON array of {category, start, end}
# objects. Anything else is treated as zero findings.
DEFAULT_PROMPT_TEMPLATE = """\
You are a privacy classifier. Inspect the input text below. Return a JSON
array of every span that contains PII or a secret. Each array element
has exactly these keys: "category" (one of: private_key, cloud_api_key,
database_url, jwt, secret, email, domain, internal_ip, customer_name,
private_name, private_phone, private_address, account_number, other),
"start" (integer 0-based char offset, inclusive), "end" (integer 0-based
char offset, exclusive). Do not include any prose. If no spans qualify,
return an empty array []. Output ONLY the JSON array.

INPUT:
{0}

OUTPUT:
"""

# Map judge-emitted category strings onto the Category enum. Unknown
# strings fall back to Category.OTHER so the action engine still sees
# the finding for audit purposes.
_CATEGORY_MAP: dict[str, Category] = {c.value: c for c in Category}


class LLMJudgeNotImplemented(NotImplementedError):
    """Kept as a re-export for callers that imported the v1 stub. The
    Day-8 implementation no longer raises; this class exists so existing
    `from ... import LLMJudgeNotImplemented` does not break."""


class LLMJudgeDetector(DetectorAdapter):
    name: ClassVar[str] = "llm_judge"

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        prompt_template: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout_s = timeout_s
        self._prompt_template = prompt_template or _load_prompt_template()
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self._client

    async def detect(self, text: str) -> list[Detection]:
        if not text:
            return []
        prompt = self._prompt_template.format(text)
        body = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                # Determinism: same input -> same output (DEC-017
                # determinism contract; LLMs need an explicit seed).
                "seed": 0,
                "temperature": 0,
            },
        }
        try:
            client = await self._http()
            resp = await client.post(f"{self._base_url}/api/generate", json=body)
            resp.raise_for_status()
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.warning(
                "llm_judge unreachable or timed out: %s; returning zero detections",
                type(exc).__name__,
            )
            return []
        try:
            payload = resp.json()
        except (json.JSONDecodeError, ValueError):
            logger.warning("llm_judge returned non-JSON envelope; returning zero detections")
            return []
        raw_response = str(payload.get("response", "")).strip()
        return _parse_judge_response(raw_response, original_text=text, detector_name=self.name)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _load_prompt_template() -> str:
    if DEFAULT_PROMPT_PATH:
        try:
            return Path(DEFAULT_PROMPT_PATH).read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning(
                "llm_judge prompt path %s unreadable (%s); falling back to default",
                DEFAULT_PROMPT_PATH,
                exc,
            )
    return DEFAULT_PROMPT_TEMPLATE


# Permissive JSON-array extractor. The LLM may emit prose around the
# array; we pull out the first `[ ... ]` substring that parses as JSON.
_JSON_ARRAY_RE = re.compile(r"\[(?:.|\n)*\]", re.DOTALL)


def _parse_judge_response(
    raw: str,
    *,
    original_text: str,
    detector_name: str,
) -> list[Detection]:
    """Tolerant parser. Malformed output -> zero detections + warning."""
    if not raw:
        return []
    # Direct JSON parse first.
    parsed: Any = None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        match = _JSON_ARRAY_RE.search(raw)
        if match is None:
            logger.warning("llm_judge response has no JSON array; ignoring")
            return []
        try:
            parsed = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            logger.warning("llm_judge response array did not parse; ignoring")
            return []

    if not isinstance(parsed, list):
        logger.warning("llm_judge top-level not a list; ignoring")
        return []

    out: list[Detection] = []
    text_len = len(original_text)
    for i, item in enumerate(parsed):
        if not isinstance(item, dict):
            continue
        category_str = str(item.get("category", "")).lower().strip()
        if not category_str:
            continue
        category = _CATEGORY_MAP.get(category_str, Category.OTHER)
        try:
            start = int(item["start"])
            end = int(item["end"])
        except (KeyError, TypeError, ValueError):
            continue
        # Defensive bounds: an out-of-range or inverted span is a model
        # mistake; drop rather than raise.
        if start < 0 or end > text_len or start >= end:
            continue
        matched = original_text[start:end]
        out.append(
            Detection(
                category=category,
                start=start,
                end=end,
                matched_text=matched,
                # The judge does not return a confidence; we record a
                # mid-range value so policies that gate on min_confidence
                # treat its findings consistently.
                confidence=0.6,
                detector=f"{detector_name}:{category.value}",
            )
        )
    return out
