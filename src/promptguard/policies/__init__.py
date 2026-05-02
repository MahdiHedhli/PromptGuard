"""Policy adapters. v1.1 ships LocalYAML as the reference adapter; Git
manifest is scaffolded. Microsoft Purview and ICAP integrations are a
v2 work item shipped on engagement (see docs/v2-roadmap.md)."""

from promptguard.policies.base import PolicyAdapter
from promptguard.policies.factory import (
    PolicySourceError,
    build_policy_adapter_from_env,
)
from promptguard.policies.git_manifest import GitManifestPolicy
from promptguard.policies.local_yaml import LocalYAMLPolicy, PolicySchemaError

__all__ = [
    "GitManifestPolicy",
    "LocalYAMLPolicy",
    "PolicyAdapter",
    "PolicySchemaError",
    "PolicySourceError",
    "build_policy_adapter_from_env",
]
