"""ICAPPolicy: PoC stub for ICAP (RFC 3507) integration.

v1 ships sample request fixtures so the wire shape is observable.
Real Symantec / Forcepoint / Trellix testing is v1.1.
"""

from __future__ import annotations

from promptguard.core.policy import Policy


class ICAPPolicy:
    name: str = "icap"

    def __init__(self, server_url: str | None = None) -> None:
        self._server_url = server_url

    def load(self) -> Policy:
        raise NotImplementedError(
            "ICAPPolicy is a v1 PoC stub. "
            "Sample ICAP request fixtures land with the adapter-framework work in days 6-7."
        )
