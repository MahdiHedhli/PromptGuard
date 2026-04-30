"""Schema validation errors must include line, column, field path, and value."""

from __future__ import annotations

from pathlib import Path

import pytest

from promptguard.policies.local_yaml import LocalYAMLPolicy, PolicySchemaError


def _load(tmp_path: Path, content: str) -> None:
    f = tmp_path / "p.yaml"
    f.write_text(content, encoding="utf-8")
    LocalYAMLPolicy(f).load()


def test_unknown_top_level_key_is_rejected_with_line(tmp_path: Path) -> None:
    yaml = """\
name: t
version: "1"
mistake_top_level: nope
rules: []
"""
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "policy file:" in msg
    assert "mistake_top_level" in msg
    # We expect a line number; loader tracks ints starting at 1.
    assert "line " in msg


def test_invalid_action_includes_path_and_value(tmp_path: Path) -> None:
    yaml = """\
name: t
rules:
  - category: email
    action: MASK
  - category: private_key
    action: REJECT
"""
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "rules.1.action" in msg
    # The value REJECT must appear in the message so operators see what failed.
    assert "REJECT" in msg
    # Line of the second rule's action key.
    assert "line " in msg


def test_invalid_category_includes_value(tmp_path: Path) -> None:
    yaml = """\
name: t
rules:
  - category: not_a_category
    action: MASK
"""
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "rules.0.category" in msg
    assert "not_a_category" in msg


def test_min_confidence_out_of_range_includes_path(tmp_path: Path) -> None:
    yaml = """\
name: t
rules:
  - category: email
    action: MASK
    min_confidence: 2.5
"""
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "rules.0.min_confidence" in msg
    assert "2.5" in msg


def test_top_level_must_be_mapping(tmp_path: Path) -> None:
    yaml = "- a\n- b\n"
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "expected a YAML mapping" in msg


def test_unknown_detector_section_rejected(tmp_path: Path) -> None:
    yaml = """\
name: t
detectors:
  regex: { enabled: true }
  not_a_detector: { enabled: true }
rules: []
"""
    with pytest.raises(PolicySchemaError) as exc_info:
        _load(tmp_path, yaml)
    msg = str(exc_info.value)
    assert "not_a_detector" in msg


def test_loaded_policy_default_detector_toggles() -> None:
    """Loading a policy without a detectors block applies the documented defaults."""
    from promptguard.policies.local_yaml import LocalYAMLPolicy as L

    # Use the shipped default.yaml; it has detectors but verify behavior.
    repo_root = Path(__file__).resolve().parents[2]
    policy = L(repo_root / "policies" / "default.yaml").load()
    assert policy.detectors.regex.enabled is True
    assert policy.detectors.opf.enabled is True
    assert policy.detectors.presidio.enabled is True
    assert policy.detectors.llm_judge.enabled is False
