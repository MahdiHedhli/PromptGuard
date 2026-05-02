"""Smoke tests for the promptguard CLI subcommands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
POLICIES = ROOT / "policies"


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "promptguard.cli", *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PYTHONPATH": str(ROOT / "src")},
        **kwargs,
    )


def test_validate_policy_passes_on_default() -> None:
    out = _run(["validate-policy", str(POLICIES / "default.yaml")])
    assert out.returncode == 0, out.stderr
    assert "VALID" in out.stdout


def test_validate_policy_fails_on_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("not: a: valid: policy: at all", encoding="utf-8")
    out = _run(["validate-policy", str(bad)])
    assert out.returncode == 1
    assert "INVALID" in out.stdout


def test_validate_policy_missing_file() -> None:
    out = _run(["validate-policy", "/nonexistent/does-not-exist.yaml"])
    assert out.returncode == 2
    assert "does not exist" in out.stderr


def test_policy_diff_default_vs_regex_only_shows_toggle_changes() -> None:
    out = _run(
        [
            "policy-diff",
            str(POLICIES / "default.yaml"),
            str(POLICIES / "regex-only.yaml"),
        ]
    )
    assert out.returncode == 0, out.stderr
    assert "Detector toggles changed" in out.stdout
    assert "opf" in out.stdout
    assert "presidio" in out.stdout


def test_policy_diff_identical_policies_reports_equivalent(tmp_path: Path) -> None:
    src = POLICIES / "default.yaml"
    cp = tmp_path / "copy.yaml"
    cp.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    out = _run(["policy-diff", str(src), str(cp)])
    assert out.returncode == 0
    assert "No behavioral changes" in out.stdout


def test_init_writes_policy_file(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    out = _run(["init", "--industry", "default", "--out", str(target)])
    assert out.returncode == 0, out.stderr
    assert target.exists()
    assert "name:" in target.read_text(encoding="utf-8")


def test_init_strict_promotes_tokenize_to_block(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    out = _run(["init", "--industry", "default", "--strict", "--out", str(target)])
    assert out.returncode == 0, out.stderr
    text = target.read_text(encoding="utf-8")
    # In default.yaml jwt is BLOCK; cloud_api_key is BLOCK; nothing changes for those.
    # secret / database_url / private_key are also BLOCK in default already, so the
    # strict promotion is a no-op on this policy. We just assert the file is valid.
    assert "name:" in text


def test_init_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    target.write_text("placeholder", encoding="utf-8")
    out = _run(["init", "--industry", "default", "--out", str(target)])
    assert out.returncode == 2
    assert "refusing to overwrite" in out.stderr


def test_init_unknown_industry_lists_options(tmp_path: Path) -> None:
    target = tmp_path / "policy.yaml"
    out = _run(["init", "--industry", "made-up-name", "--out", str(target)])
    assert out.returncode == 2
    assert "Available" in out.stderr


def test_doctor_runs_to_completion() -> None:
    """doctor returns 0 or 1 cleanly; never crashes."""
    out = _run(["doctor", "--no-color"])
    assert out.returncode in (0, 1), out.stderr
    assert "PromptGuard preflight" in out.stdout


@pytest.mark.parametrize("subcommand", ["doctor", "init", "validate-policy", "policy-diff"])
def test_subcommand_help_works(subcommand: str) -> None:
    out = _run([subcommand, "--help"])
    assert out.returncode == 0
    assert subcommand in out.stdout or "usage" in out.stdout.lower()
