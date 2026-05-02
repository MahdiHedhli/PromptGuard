"""PolicyAdapter contract conformance + Purview/ICAP adapters.

Validates:

  * `LocalYAMLPolicy`, `GitManifestPolicy`, `PurviewDLPPolicy`,
    `ICAPPolicy` all subclass `PolicyAdapter`.
  * `name` class attribute is lowercase + underscore-only.
  * Loading the shipped Purview SIT fixture produces a working policy.
  * Loading the shipped ICAP fixture produces a working policy.
  * The Purview and ICAP fixtures, given the same input, agree with a
    YAML equivalent on action decisions (one-to-one translation works).
  * Schema-error paths in Purview / ICAP raise `PolicySchemaError` with
    a useful message.
  * `build_policy_adapter_from_env` honors `PROMPTGUARD_POLICY_SOURCE`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptguard.core.policy import Action, Category, Policy
from promptguard.policies import (
    GitManifestPolicy,
    ICAPPolicy,
    LocalYAMLPolicy,
    PolicyAdapter,
    PolicySchemaError,
    PolicySourceError,
    PurviewDLPPolicy,
    build_policy_adapter_from_env,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PURVIEW_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "purview" / "sample-sit-export.json"
ICAP_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "icap" / "sample-rules-response.txt"


# -- contract conformance -----------------------------------------


@pytest.mark.parametrize(
    "adapter_cls",
    [LocalYAMLPolicy, GitManifestPolicy, PurviewDLPPolicy, ICAPPolicy],
)
def test_subclasses_policy_adapter(adapter_cls) -> None:
    assert issubclass(adapter_cls, PolicyAdapter)


@pytest.mark.parametrize(
    ("adapter_cls", "expected_name"),
    [
        (LocalYAMLPolicy, "local_yaml"),
        (GitManifestPolicy, "git_manifest"),
        (PurviewDLPPolicy, "purview_dlp"),
        (ICAPPolicy, "icap"),
    ],
)
def test_name_class_attribute(adapter_cls, expected_name: str) -> None:
    assert adapter_cls.name == expected_name
    assert adapter_cls.name.islower()
    assert " " not in adapter_cls.name


# -- Purview --------------------------------------------------------


def test_purview_loads_sample_sit_export() -> None:
    adapter = PurviewDLPPolicy(PURVIEW_FIXTURE)
    policy = adapter.load()
    assert isinstance(policy, Policy)
    assert policy.name == "purview-engagement-export-2026q2"
    assert policy.version == "3"
    # Five info types translate to five rules.
    assert len(policy.rules) == 5
    # Spot-check a couple of category / action mappings.
    assert policy.action_for(Category.PRIVATE_KEY, 1.0) == Action.BLOCK
    assert policy.action_for(Category.CUSTOMER_NAME, 1.0) == Action.BLOCK
    assert policy.action_for(Category.INTERNAL_IP, 1.0) == Action.MASK


def test_purview_min_confidence_floor_respected() -> None:
    adapter = PurviewDLPPolicy(PURVIEW_FIXTURE)
    policy = adapter.load()
    # private-key fixture has minConfidence 0.95
    assert policy.action_for(Category.PRIVATE_KEY, 0.94) == Action.ALLOW
    assert policy.action_for(Category.PRIVATE_KEY, 0.95) == Action.BLOCK


def test_purview_rejects_unknown_category(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "policyName": "bad",
                "informationTypes": [
                    {
                        "id": "x",
                        "displayName": "x",
                        "promptguardCategory": "not_a_real_category",
                        "recommendedAction": "BLOCK",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicySchemaError) as exc:
        PurviewDLPPolicy(bad).load()
    assert "promptguardCategory" in str(exc.value)


def test_purview_rejects_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(PolicySchemaError):
        PurviewDLPPolicy(bad).load()


def test_purview_rejects_duplicate_categories(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "policyName": "dup",
                "informationTypes": [
                    {
                        "promptguardCategory": "email",
                        "recommendedAction": "MASK",
                    },
                    {
                        "promptguardCategory": "email",
                        "recommendedAction": "BLOCK",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PolicySchemaError) as exc:
        PurviewDLPPolicy(bad).load()
    assert "duplicates" in str(exc.value).lower()


# -- ICAP -----------------------------------------------------------


def test_icap_loads_sample_fixture() -> None:
    adapter = ICAPPolicy(ICAP_FIXTURE)
    policy = adapter.load()
    assert isinstance(policy, Policy)
    assert policy.name.startswith("icap-")
    # The shipped fixture defines nine rules.
    assert len(policy.rules) == 9
    assert policy.action_for(Category.PRIVATE_KEY, 1.0) == Action.BLOCK
    assert policy.action_for(Category.INTERNAL_IP, 1.0) == Action.TOKENIZE
    assert policy.action_for(Category.EMAIL, 1.0) == Action.MASK


def test_icap_rejects_unknown_action(tmp_path: Path) -> None:
    bad = tmp_path / "bad.icap"
    bad.write_text(
        "ICAP/1.0 200 OK\nServer: test\n\n"
        "private_key\tREJECT\t0.95\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicySchemaError) as exc:
        ICAPPolicy(bad).load()
    assert "unknown action" in str(exc.value).lower()


def test_icap_rejects_missing_separator(tmp_path: Path) -> None:
    bad = tmp_path / "bad.icap"
    bad.write_text("ICAP/1.0 200 OK\nServer: test", encoding="utf-8")
    with pytest.raises(PolicySchemaError):
        ICAPPolicy(bad).load()


def test_icap_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    f = tmp_path / "ok.icap"
    f.write_text(
        "ICAP/1.0 200 OK\nServer: test\n\n"
        "# comment\n"
        "\n"
        "email\tMASK\t0.5\n"
        "  # another comment with leading whitespace\n"
        "private_key\tBLOCK\n",  # min_conf optional
        encoding="utf-8",
    )
    policy = ICAPPolicy(f).load()
    assert len(policy.rules) == 2


# -- One-to-one equivalence: Purview YAML PolicyRule = ICAP body row -


def test_purview_and_yaml_agree_on_subset_of_rules(tmp_path: Path) -> None:
    """Same translation logic must yield the same policy."""
    yaml_equiv = tmp_path / "equiv.yaml"
    yaml_equiv.write_text(
        """\
name: equiv
detectors: { regex: { enabled: true }, opf: { enabled: true }, presidio: { enabled: true } }
rules:
  - { category: private_key, action: BLOCK, min_confidence: 0.95 }
  - { category: cloud_api_key, action: BLOCK, min_confidence: 0.9 }
""",
        encoding="utf-8",
    )
    purview_equiv = tmp_path / "equiv.json"
    purview_equiv.write_text(
        json.dumps(
            {
                "policyName": "equiv",
                "informationTypes": [
                    {
                        "promptguardCategory": "private_key",
                        "recommendedAction": "BLOCK",
                        "minConfidence": 0.95,
                    },
                    {
                        "promptguardCategory": "cloud_api_key",
                        "recommendedAction": "BLOCK",
                        "minConfidence": 0.9,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    yaml_policy = LocalYAMLPolicy(yaml_equiv).load()
    purview_policy = PurviewDLPPolicy(purview_equiv).load()
    for cat in (Category.PRIVATE_KEY, Category.CLOUD_API_KEY):
        for conf in (0.5, 0.9, 0.95, 1.0):
            assert yaml_policy.action_for(cat, conf) == purview_policy.action_for(
                cat, conf
            ), f"mismatch on {cat.value} at conf={conf}"


# -- factory --------------------------------------------------------


def test_factory_default_is_local_yaml(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PROMPTGUARD_POLICY_SOURCE", raising=False)
    monkeypatch.setenv("PROMPTGUARD_POLICY_FILE", str(REPO_ROOT / "policies" / "default.yaml"))
    adapter = build_policy_adapter_from_env()
    assert isinstance(adapter, LocalYAMLPolicy)


def test_factory_dispatches_purview_dlp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROMPTGUARD_POLICY_SOURCE", "purview_dlp")
    monkeypatch.setenv("PROMPTGUARD_POLICY_FILE", str(PURVIEW_FIXTURE))
    adapter = build_policy_adapter_from_env()
    assert isinstance(adapter, PurviewDLPPolicy)
    # And it actually loads.
    policy = adapter.load()
    assert policy.name == "purview-engagement-export-2026q2"


def test_factory_dispatches_icap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROMPTGUARD_POLICY_SOURCE", "icap")
    monkeypatch.setenv("PROMPTGUARD_POLICY_FILE", str(ICAP_FIXTURE))
    adapter = build_policy_adapter_from_env()
    assert isinstance(adapter, ICAPPolicy)


def test_factory_rejects_unknown_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROMPTGUARD_POLICY_SOURCE", "nonsense")
    with pytest.raises(PolicySourceError):
        build_policy_adapter_from_env()
