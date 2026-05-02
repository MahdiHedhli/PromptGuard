"""Policy-source factory: pick the right adapter from a config dict / env.

The proxy reads `PROMPTGUARD_POLICY_SOURCE` (default `local_yaml`) and
`PROMPTGUARD_POLICY_FILE` to build a `PolicyAdapter` at startup. This
module is the one place that knows about every shipped adapter, so
swapping policy sources is a one-line config change for the operator.

v1 validation gate: a user can swap policy source by changing
`PROMPTGUARD_POLICY_SOURCE`. No code changes needed in the proxy hook
or anywhere else.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from promptguard.policies.base import PolicyAdapter
from promptguard.policies.git_manifest import GitManifestPolicy
from promptguard.policies.local_yaml import LocalYAMLPolicy

DEFAULT_SOURCE: Final[str] = "local_yaml"
DEFAULT_PATH: Final[str] = "/app/policies/default.yaml"


class PolicySourceError(ValueError):
    """Operator error: unknown policy source."""


def build_policy_adapter_from_env() -> PolicyAdapter:
    """Construct the configured adapter. Raises on unknown source."""
    source = os.environ.get("PROMPTGUARD_POLICY_SOURCE", DEFAULT_SOURCE).strip()
    path = os.environ.get("PROMPTGUARD_POLICY_FILE", DEFAULT_PATH)
    return _build(source, path)


def _build(source: str, path: str) -> PolicyAdapter:
    source_lower = source.lower()
    if source_lower == "local_yaml":
        return LocalYAMLPolicy(path)
    if source_lower == "git_manifest":
        # GitManifestPolicy still raises NotImplementedError on load();
        # surfaces a clean error at proxy startup rather than a cryptic
        # "no module named" or similar.
        return GitManifestPolicy(repo_url=path)
    if source_lower in {"purview_dlp", "icap"}:
        raise PolicySourceError(
            f"PROMPTGUARD_POLICY_SOURCE={source!r} requires the v2 "
            f"integrations (Microsoft Purview / ICAP). v1.1 ships only "
            f"the local_yaml adapter; the v2 integrations are delivered "
            f"on engagement. See docs/v2-roadmap.md."
        )
    raise PolicySourceError(
        f"unknown PROMPTGUARD_POLICY_SOURCE={source!r}; "
        f"valid values: local_yaml, git_manifest"
    )
