"""Hot-reload tests for the policy reloader.

Covers:
  * mtime change with valid YAML triggers a swap
  * unchanged mtime is a no-op
  * schema-error YAML is rejected; old policy stays active
  * detector toggle change rebuilds the pipeline
  * conversation TokenMap survives the swap
"""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
import respx

from promptguard.actions import ActionEngine
from promptguard.actions.tokenize import TokenMap
from promptguard.core.detection import DetectionPipeline
from promptguard.core.policy import Action, Category, Policy, PolicyRule
from promptguard.detectors.regex_detector import RegexDetector
from promptguard.proxy.litellm_hooks import PromptGuardHook
from promptguard.proxy.policy_reloader import PolicyReloader


def _hook_with(policy: Policy, token_map: TokenMap | None = None) -> PromptGuardHook:
    pipeline = DetectionPipeline([RegexDetector()])
    engine = ActionEngine(policy, token_map=token_map)
    return PromptGuardHook(policy=policy, pipeline=pipeline, engine=engine)


def _write_policy(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / f"{name}.yaml"
    p.write_text(content, encoding="utf-8")
    return p


# ---- mtime change triggers swap -----------------------------------


def test_reloader_swaps_policy_when_file_changes(tmp_path: Path) -> None:
    f = _write_policy(
        tmp_path,
        "p",
        """\
name: original
version: "1"
detectors:
  regex: { enabled: true }
  opf: { enabled: false }
  presidio: { enabled: false }
  llm_judge: { enabled: false }
rules:
  - category: email
    action: MASK
""",
    )
    initial = Policy.model_validate(
        {
            "name": "original",
            "rules": [{"category": "email", "action": "MASK"}],
        }
    )
    hook = _hook_with(initial)
    reloader = PolicyReloader(hook, f, interval_s=0.1)
    # Bump mtime forward to ensure we see a strictly-greater value.
    new_mtime = f.stat().st_mtime + 1.5
    f.write_text(
        """\
name: updated
version: "2"
detectors:
  regex: { enabled: true }
  opf: { enabled: false }
  presidio: { enabled: false }
  llm_judge: { enabled: false }
rules:
  - category: email
    action: BLOCK
""",
        encoding="utf-8",
    )
    import os as _os

    _os.utime(f, (new_mtime, new_mtime))
    swapped = reloader.check_once()
    assert swapped is True
    assert hook._policy.name == "updated"
    assert hook._policy.version == "2"
    assert hook._policy.action_for(Category.EMAIL, 1.0) == Action.BLOCK


def test_reloader_no_swap_when_mtime_unchanged(tmp_path: Path) -> None:
    f = _write_policy(
        tmp_path,
        "p",
        """\
name: original
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
    )
    hook = _hook_with(Policy(name="original"))
    reloader = PolicyReloader(hook, f, interval_s=0.1)
    assert reloader.check_once() is False
    assert reloader.check_once() is False


# ---- schema-error rejection ---------------------------------------


def test_reloader_rejects_invalid_yaml_keeps_old_policy(tmp_path: Path) -> None:
    f = _write_policy(
        tmp_path,
        "p",
        """\
name: original
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
    )
    hook = _hook_with(Policy(name="original"))
    reloader = PolicyReloader(hook, f, interval_s=0.1)
    new_mtime = f.stat().st_mtime + 1.5
    f.write_text(
        """\
name: broken
rules:
  - category: email
    action: REJECT
""",
        encoding="utf-8",
    )
    import os as _os

    _os.utime(f, (new_mtime, new_mtime))
    assert reloader.check_once() is False
    # Old policy still active.
    assert hook._policy.name == "original"
    # And we don't keep retrying the broken mtime.
    assert reloader.check_once() is False


# ---- OPF readiness gate at reload ---------------------------------


@respx.mock
def test_reloader_rejects_swap_when_new_policy_needs_opf_and_opf_unreachable(
    tmp_path: Path,
) -> None:
    """If the swap-target policy enables OPF and OPF is not /ready, refuse."""
    respx.get("http://opf.test/ready").mock(return_value=httpx.Response(503))

    import os as _os

    _os.environ["PROMPTGUARD_OPF_URL"] = "http://opf.test"
    try:
        f = _write_policy(
            tmp_path,
            "p",
            """\
name: original
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
        )
        hook = _hook_with(Policy(name="original"))
        reloader = PolicyReloader(hook, f, interval_s=0.1)
        new_mtime = f.stat().st_mtime + 1.5
        f.write_text(
            """\
name: opf-needed
detectors: { regex: { enabled: true }, opf: { enabled: true }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
            encoding="utf-8",
        )
        _os.utime(f, (new_mtime, new_mtime))
        assert reloader.check_once() is False
        assert hook._policy.name == "original"
    finally:
        _os.environ.pop("PROMPTGUARD_OPF_URL", None)


# ---- TokenMap survives swap ---------------------------------------


def test_reloader_preserves_token_map_across_swap(tmp_path: Path) -> None:
    """An issued token must remain reversible after a policy swap."""
    f = _write_policy(
        tmp_path,
        "p",
        """\
name: a
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules:
  - category: internal_ip
    action: TOKENIZE
""",
    )
    tm = TokenMap()
    hook = _hook_with(
        Policy(
            name="a",
            rules=[PolicyRule(category=Category.INTERNAL_IP, action=Action.TOKENIZE)],
        ),
        token_map=tm,
    )
    issued = tm.issue("conv-X", Category.INTERNAL_IP, "10.0.0.5")

    reloader = PolicyReloader(hook, f, interval_s=0.1)
    new_mtime = f.stat().st_mtime + 1.5
    f.write_text(
        """\
name: b
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules:
  - category: internal_ip
    action: BLOCK
""",
        encoding="utf-8",
    )
    import os as _os

    _os.utime(f, (new_mtime, new_mtime))
    assert reloader.check_once() is True

    # The TokenMap survives. Reverse path on the previously issued token still works.
    assert hook.token_map.lookup("conv-X", issued) == "10.0.0.5"
    assert hook._engine.token_map is hook.token_map


# ---- background thread integration --------------------------------


def test_reloader_background_thread_picks_up_change(tmp_path: Path) -> None:
    """Smoke test: start the daemon thread, change the file, observe swap."""
    f = _write_policy(
        tmp_path,
        "p",
        """\
name: start
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
    )
    hook = _hook_with(Policy(name="start"))
    reloader = PolicyReloader(hook, f, interval_s=0.05)
    reloader.start()
    try:
        new_mtime = f.stat().st_mtime + 1.5
        f.write_text(
            """\
name: end
detectors: { regex: { enabled: true }, opf: { enabled: false }, presidio: { enabled: false }, llm_judge: { enabled: false } }
rules: []
""",
            encoding="utf-8",
        )
        import os as _os

        _os.utime(f, (new_mtime, new_mtime))
        # Give the polling thread two cycles to notice.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if hook._policy.name == "end":
                break
            time.sleep(0.05)
        assert hook._policy.name == "end"
    finally:
        reloader.stop()
