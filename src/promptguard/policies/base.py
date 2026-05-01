"""PolicyAdapter contract.

A `PolicyAdapter` knows how to fetch a `Policy` from some source and
return it. v1 ships `LocalYAMLPolicy` as the reference implementation;
`GitManifestPolicy`, `PurviewDLPPolicy`, and `ICAPPolicy` are scaffolded
so the adapter framework is observable in the codebase. Real
fetch-from-network for the latter three is v1.1 work; the parsing /
translation paths are real where sample fixtures ship in v1.

# Contract

A `PolicyAdapter` produces a `Policy` instance ready for use by the
proxy. The contract has three binding rules:

1. **Same shape, same target.** Every adapter returns a `Policy` that
   conforms to `promptguard.core.policy.Policy`. The action engine
   does not know or care which adapter loaded the policy.

2. **Schema validation is the adapter's job.** The adapter is the
   layer that translates from the source format (YAML, JSON, XML, ICAP,
   Purview API) to PromptGuard categories and actions. If the source
   format is malformed, raise `PolicySchemaError` with a clear message
   that includes the source location (line/column for textual sources,
   field path for structured sources).

3. **Fail loud, never silent.** A misconfigured policy at startup
   means the proxy refuses to start (per DEC-009 and the broader
   threat-model commitment). Adapters MUST raise on failure rather
   than returning an empty or default-allow policy.

# Optional methods

The base class declares `name` (operator-facing label, used in logs)
and `load()` (returns a `Policy`). v1.1 may add `subscribe(callback)`
for adapters that can push policy updates rather than being polled by
the hot-reloader. Not part of v1 contract.

# Naming

`name` convention: lowercase, underscores. Standard names:
`local_yaml`, `git_manifest`, `purview_dlp`, `icap`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from promptguard.core.policy import Policy


class PolicyAdapter(ABC):
    """Abstract base for all policy sources.

    Concrete adapters set `name` and implement `load`. v1 keeps the
    interface synchronous because every shipped adapter loads from
    local sources (file system, in-process fixture). v1.1 may add an
    async parallel `aload()` for adapters that fetch over the network
    (real Purview Graph API, real ICAP server).
    """

    name: ClassVar[str] = "abstract"

    @abstractmethod
    def load(self) -> Policy:
        """Return the current policy.

        Raises `PolicySchemaError` (or a subclass) on schema /
        translation failure. The hook startup path treats this as
        fatal and refuses to serve traffic.
        """
