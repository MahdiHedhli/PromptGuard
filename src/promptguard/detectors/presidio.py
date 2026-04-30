"""Stage-3 Presidio detector.

Talks to the Microsoft Presidio analyzer container over its HTTP API.
The analyzer accepts text + a list of entity types and returns spans.

We map Presidio entity types onto our Category vocabulary. Org-specific
custom recognizers loaded into the analyzer (codenames, customer names)
should report through the standard Presidio entity-type mechanism.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from promptguard.core.detection import Detection
from promptguard.core.policy import Category

DEFAULT_BASE_URL = os.environ.get(
    "PROMPTGUARD_PRESIDIO_URL", "http://localhost:5002"
)
DEFAULT_TIMEOUT_S = float(os.environ.get("PROMPTGUARD_PRESIDIO_TIMEOUT_S", "10.0"))
DEFAULT_LANGUAGE = os.environ.get("PROMPTGUARD_PRESIDIO_LANGUAGE", "en")

PRESIDIO_ENTITY_TO_CATEGORY: dict[str, Category] = {
    "EMAIL_ADDRESS": Category.EMAIL,
    "PHONE_NUMBER": Category.PRIVATE_PHONE,
    "PERSON": Category.PRIVATE_NAME,
    "LOCATION": Category.PRIVATE_ADDRESS,
    "IP_ADDRESS": Category.INTERNAL_IP,
    "URL": Category.DOMAIN,
    "CREDIT_CARD": Category.ACCOUNT_NUMBER,
    "IBAN_CODE": Category.ACCOUNT_NUMBER,
    "US_BANK_NUMBER": Category.ACCOUNT_NUMBER,
    "US_SSN": Category.ACCOUNT_NUMBER,
    "CUSTOMER_NAME": Category.CUSTOMER_NAME,
}


class PresidioDetector:
    name: str = "presidio"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        language: str = DEFAULT_LANGUAGE,
        entities: list[str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s
        self._language = language
        self._entities = entities
        self._client = client

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout_s)
        return self._client

    async def detect(self, text: str) -> list[Detection]:
        body: dict[str, Any] = {"text": text, "language": self._language}
        if self._entities is not None:
            body["entities"] = self._entities
        client = await self._http()
        resp = await client.post(f"{self._base_url}/analyze", json=body)
        resp.raise_for_status()
        return _parse_detections(resp.json(), detector_name=self.name)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def _parse_detections(payload: Any, *, detector_name: str) -> list[Detection]:
    # Presidio returns a list[dict], not {"detections": [...]}. Be lenient.
    items: list[dict[str, Any]]
    if isinstance(payload, dict) and "detections" in payload:
        items = payload["detections"]
    elif isinstance(payload, list):
        items = payload
    else:
        items = []
    out: list[Detection] = []
    for item in items:
        entity_type = str(item.get("entity_type", "")).upper()
        category = PRESIDIO_ENTITY_TO_CATEGORY.get(entity_type, Category.OTHER)
        out.append(
            Detection(
                category=category,
                start=int(item["start"]),
                end=int(item["end"]),
                matched_text=str(item.get("text", "")),
                confidence=float(item.get("score", 0.0)),
                detector=f"{detector_name}:{entity_type or 'unknown'}",
            )
        )
    return out
