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

# OPF released 2026-04-22 with these eight categories (see research-notes section 6).
# Categories not present in our vocabulary fall back to OTHER for visibility.
OPF_LABEL_TO_CATEGORY: dict[str, Category] = {
    "account_number": Category.ACCOUNT_NUMBER,
    "private_address": Category.PRIVATE_ADDRESS,
    "private_email": Category.EMAIL,
    "private_name": Category.PRIVATE_NAME,
    "private_phone": Category.PRIVATE_PHONE,
    "secret": Category.SECRET,
    "private_date": Category.OTHER,
    "background": Category.OTHER,
}


class OPFDetector(DetectorAdapter):
    name: ClassVar[str] = "opf"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self._client

    async def detect(self, text: str) -> list[Detection]:
        client = await self._http()
        resp = await client.post(f"{self._base_url}/detect", json={"text": text})
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
