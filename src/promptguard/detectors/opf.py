"""Stage-2 OPF detector.

Talks to the `opf-service` container over HTTP. The service wraps the
HuggingFace `openai/privacy-filter` token-classification pipeline.

Service contract (see src/promptguard/services/opf_service/server.py):

    POST /detect
    { "text": "..." }
    -> 200 { "detections": [
        { "label": "private_email", "start": 0, "end": 12, "score": 0.97,
          "text": "x@example.com" },
        ...
    ]}

OPF labels are mapped onto our Category vocabulary; unknown labels are
reported as Category.OTHER so policy authors can see them in audit logs.
"""

from __future__ import annotations

import os
from typing import Any, ClassVar

import httpx

from promptguard.core.detection import Detection
from promptguard.core.policy import Category
from promptguard.detectors.base import DetectorAdapter

DEFAULT_BASE_URL = os.environ.get("PROMPTGUARD_OPF_URL", "http://localhost:8081")
DEFAULT_TIMEOUT_S = float(os.environ.get("PROMPTGUARD_OPF_TIMEOUT_S", "10.0"))

# OPF (openai/privacy-filter) emits these labels. Empirically verified
# on the model the v1.1.1 benchmarks ran against:
#   private_person, private_email, private_address, private_phone,
#   private_date, private_url, account_number, secret, private_id,
#   background.
# Categories not present in PromptGuard's vocabulary fall back to OTHER
# for visibility. We map `private_person` -> PRIVATE_NAME (the model's
# internal label name; PromptGuard uses PRIVATE_NAME externally to be
# consistent with Presidio's PERSON recognizer).
OPF_LABEL_TO_CATEGORY: dict[str, Category] = {
    "account_number": Category.ACCOUNT_NUMBER,
    "private_address": Category.PRIVATE_ADDRESS,
    "private_email": Category.EMAIL,
    "private_name": Category.PRIVATE_NAME,
    "private_person": Category.PRIVATE_NAME,
    "private_phone": Category.PRIVATE_PHONE,
    "secret": Category.SECRET,
    "private_date": Category.OTHER,
    "private_url": Category.DOMAIN,
    "private_id": Category.OTHER,
    "background": Category.OTHER,
}


class OPFDetector(DetectorAdapter):
    name: ClassVar[str] = "opf"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        client: httpx.AsyncClient | None = None,
        aggregation_strategy: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._client = client
        # None -> use the service's DEFAULT_AGGREGATION ("simple" out of
        # the box). Pass "max" / "first" / "average" to opt into a
        # recall-tuned operating point. See DEC-026 + docs/benchmarks.md
        # for the published default vs recall-tuned comparison.
        self._aggregation_strategy = aggregation_strategy

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self._client

    async def detect(self, text: str) -> list[Detection]:
        client = await self._http()
        body: dict[str, Any] = {"text": text}
        if self._aggregation_strategy is not None:
            body["aggregation_strategy"] = self._aggregation_strategy
        resp = await client.post(f"{self._base_url}/detect", json=body)
        resp.raise_for_status()
        payload: dict[str, Any] = resp.json()
        return _parse_detections(payload, detector_name=self.name)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _parse_detections(payload: dict[str, Any], *, detector_name: str) -> list[Detection]:
    raw = payload.get("detections", [])
    out: list[Detection] = []
    for item in raw:
        label = str(item.get("label", "")).lower()
        category = OPF_LABEL_TO_CATEGORY.get(label, Category.OTHER)
        out.append(
            Detection(
                category=category,
                start=int(item["start"]),
                end=int(item["end"]),
                matched_text=str(item.get("text", "")),
                confidence=float(item.get("score", 0.0)),
                detector=f"{detector_name}:{label or 'unknown'}",
            )
        )
    return out
