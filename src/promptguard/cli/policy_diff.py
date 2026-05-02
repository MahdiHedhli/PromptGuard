"""`promptguard policy-diff` behavioral delta.

Compares two policy YAML files and prints a human-readable summary
of what changed. The diff is at the *behavioral* level (what the
proxy will do differently for a given category at a given confidence)
rather than line-level YAML.

Output sections:
  * Detector toggles changed
  * Rules added (category x action)
  * Rules removed
  * Rules with action / threshold changes
  * Audit-only flag changes
"""

from __future__ import annotations

import sys
from pathlib import Path

from promptguard.core.policy import Policy, PolicyRule
from promptguard.policies.local_yaml import LocalYAMLPolicy


def _rule_key(rule: PolicyRule) -> tuple[str, float]:
    return (rule.category.value, float(rule.min_confidence))


def _detector_state(p: Policy) -> dict[str, bool]:
    d = p.detectors
    return {
        "regex": d.regex.enabled,
        "opf": d.opf.enabled,
        "presidio": d.presidio.enabled,
        "normalization": d.normalization.enabled,
    }


def run_policy_diff(*, old: str, new: str) -> int:
    try:
        old_p = LocalYAMLPolicy(Path(old)).load()
        new_p = LocalYAMLPolicy(Path(new)).load()
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"--- {old}")
    print(f"+++ {new}")

    # Detector toggles
    old_dets = _detector_state(old_p)
    new_dets = _detector_state(new_p)
    toggle_diffs = [
        (k, old_dets[k], new_dets[k]) for k in old_dets if old_dets[k] != new_dets[k]
    ]
    if toggle_diffs:
        print()
        print("Detector toggles changed:")
        for name, old_v, new_v in toggle_diffs:
            print(f"  - {name}: {old_v} -> {new_v}")

    # Rules indexed by (category, min_confidence)
    old_rules = {_rule_key(r): r for r in old_p.rules}
    new_rules = {_rule_key(r): r for r in new_p.rules}

    added = [k for k in new_rules if k not in old_rules]
    removed = [k for k in old_rules if k not in new_rules]
    common = [k for k in old_rules if k in new_rules]

    if added:
        print()
        print("Rules added:")
        for k in added:
            r = new_rules[k]
            ao = " (audit_only)" if r.audit_only else ""
            print(f"  + {r.category.value} @ >= {r.min_confidence:.2f} -> {r.action.value}{ao}")

    if removed:
        print()
        print("Rules removed:")
        for k in removed:
            r = old_rules[k]
            ao = " (audit_only)" if r.audit_only else ""
            print(f"  - {r.category.value} @ >= {r.min_confidence:.2f} -> {r.action.value}{ao}")

    changed_action = []
    changed_audit = []
    for k in common:
        old_r, new_r = old_rules[k], new_rules[k]
        if old_r.action != new_r.action:
            changed_action.append((k, old_r, new_r))
        if old_r.audit_only != new_r.audit_only:
            changed_audit.append((k, old_r, new_r))

    if changed_action:
        print()
        print("Rules with action change:")
        for (cat, conf), old_r, new_r in changed_action:
            print(
                f"  ~ {cat} @ >= {conf:.2f}: "
                f"{old_r.action.value} -> {new_r.action.value}"
            )
    if changed_audit:
        print()
        print("Rules with audit_only change:")
        for (cat, conf), old_r, new_r in changed_audit:
            print(
                f"  ~ {cat} @ >= {conf:.2f}: "
                f"audit_only {old_r.audit_only} -> {new_r.audit_only}"
            )

    if not (toggle_diffs or added or removed or changed_action or changed_audit):
        print()
        print("No behavioral changes detected. The two policies are equivalent.")

    return 0
