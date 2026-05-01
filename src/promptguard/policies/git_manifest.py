"""GitManifestPolicy: scaffold for signed-manifest pull.

Real implementation lands when the central-distribution story is
prioritized (post-v1). The shape is here so the adapter framework is
visible and policy-source plug-in points exist.
"""

from __future__ import annotations

from typing import ClassVar

from promptguard.core.policy import Policy
from promptguard.policies.base import PolicyAdapter


class GitManifestPolicy(PolicyAdapter):
    name: ClassVar[str] = "git_manifest"

    def __init__(self, repo_url: str, manifest_path: str = "policy.yaml") -> None:
        self._repo_url = repo_url
        self._manifest_path = manifest_path

    @property
    def repo_url(self) -> str:
        return self._repo_url

    def load(self) -> Policy:
        raise NotImplementedError(
            "GitManifestPolicy is scaffolded for v1.1. "
            "Use LocalYAMLPolicy for v1; central distribution arrives with signed manifests."
        )
