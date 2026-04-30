"""PolicyAdapter base contract.

A `PolicyAdapter` knows how to fetch (and re-fetch) a `Policy` from some
source. v1 ships LocalYAML as the reference; GitManifest and Purview/ICAP
are scaffolded so the adapter framework is observable in the v1 codebase.
"""

from __future__ import annotations

from typing import Protocol

from promptguard.core.policy import Policy


class PolicyAdapter(Protocol):
    """Minimal contract: load() returns a current `Policy`.

    Adapters may cache, refresh on a TTL, or hot-reload on file change.
    Day 1 ships a sync interface; if v1.1 needs async fetching (Purview),
    add a parallel `aload()` rather than retrofit `load()`.
    """

    name: str

    def load(self) -> Policy: ...
