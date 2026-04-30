"""PurviewDLPPolicy: PoC stub for Microsoft Purview DLP integration.

v1 ships sample SIT-export fixtures so the import path can be exercised
against realistic input shapes. Real Graph-API auth + classifier pull
arrives in v1.1.
"""

from __future__ import annotations

from pathlib import Path

from promptguard.core.policy import Policy


class PurviewDLPPolicy:
    name: str = "purview_dlp"

    def __init__(self, sample_export_path: str | Path | None = None) -> None:
        self._sample_export_path = Path(sample_export_path) if sample_export_path else None

    def load(self) -> Policy:
        raise NotImplementedError(
            "PurviewDLPPolicy is a v1 PoC stub. "
            "Sample SIT-export translation lands with the import-fixture work in days 6-7."
        )
