"""Policy adapters. v1 ships LocalYAML as reference; Git/Purview/ICAP scaffolded."""

from promptguard.policies.base import PolicyAdapter
from promptguard.policies.git_manifest import GitManifestPolicy
from promptguard.policies.icap_stub import ICAPPolicy
from promptguard.policies.local_yaml import LocalYAMLPolicy
from promptguard.policies.purview_stub import PurviewDLPPolicy

__all__ = [
    "GitManifestPolicy",
    "ICAPPolicy",
    "LocalYAMLPolicy",
    "PolicyAdapter",
    "PurviewDLPPolicy",
]
