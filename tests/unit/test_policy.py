from __future__ import annotations

from pathlib import Path

import pytest

from promptguard.core.policy import Action, Category, Policy, PolicyRule
from promptguard.policies.local_yaml import LocalYAMLPolicy


def test_policy_action_for_returns_default_allow() -> None:
    p = Policy(name="empty", rules=[])
    assert p.action_for(Category.EMAIL, 1.0) == Action.ALLOW


def test_policy_action_for_respects_min_confidence() -> None:
    p = Policy(
        name="conf-test",
        rules=[
            PolicyRule(category=Category.EMAIL, action=Action.MASK, min_confidence=0.8),
        ],
    )
    assert p.action_for(Category.EMAIL, 0.9) == Action.MASK
    assert p.action_for(Category.EMAIL, 0.5) == Action.ALLOW


def test_local_yaml_loads_default_policy(policies_dir: Path) -> None:
    adapter = LocalYAMLPolicy(policies_dir / "default.yaml")
    policy = adapter.load()
    assert policy.name == "default"
    assert policy.action_for(Category.PRIVATE_KEY, 1.0) == Action.BLOCK
    assert policy.action_for(Category.EMAIL, 1.0) == Action.MASK
    assert policy.action_for(Category.DOMAIN, 1.0) == Action.TOKENIZE


@pytest.mark.parametrize("policy_name", ["nda-strict", "healthcare-leaning"])
def test_local_yaml_loads_sample_policies(policies_dir: Path, policy_name: str) -> None:
    adapter = LocalYAMLPolicy(policies_dir / f"{policy_name}.yaml")
    policy = adapter.load()
    assert policy.name == policy_name
    # PrivateKey is BLOCK in every shipped policy.
    assert policy.action_for(Category.PRIVATE_KEY, 1.0) == Action.BLOCK


def test_local_yaml_missing_file_raises(tmp_path: Path) -> None:
    adapter = LocalYAMLPolicy(tmp_path / "does-not-exist.yaml")
    with pytest.raises(FileNotFoundError):
        adapter.load()


def test_local_yaml_invalid_top_level_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- this\n- is\n- a list\n", encoding="utf-8")
    adapter = LocalYAMLPolicy(bad)
    with pytest.raises(ValueError):
        adapter.load()
