"""`promptguard init` policy bootstrapper.

Copies a starter policy YAML into the operator's working directory.
With `--strict`, promotes TOKENIZE rules on sensitive categories to
BLOCK so a misconfiguration fails closed rather than open.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
POLICIES_DIR = ROOT / "policies"

# Categories where "rotate-and-restore" semantics are wrong on principle.
# In strict mode, any TOKENIZE on these flips to BLOCK.
_STRICT_BLOCK_CATEGORIES = {
    "private_key",
    "cloud_api_key",
    "secret",
    "database_url",
    "jwt",
}


def _shipped_path(industry: str) -> Path:
    candidate = POLICIES_DIR / f"{industry}.yaml"
    if candidate.exists():
        return candidate
    # Helpful error: list what is shipped.
    shipped = sorted(p.stem for p in POLICIES_DIR.glob("*.yaml"))
    raise FileNotFoundError(
        f"No shipped policy '{industry}.yaml'. "
        f"Available: {', '.join(shipped)}."
    )


def _apply_strict(policy_text: str) -> str:
    parsed = yaml.safe_load(policy_text)
    if not isinstance(parsed, dict) or "rules" not in parsed:
        return policy_text
    changed = False
    for rule in parsed.get("rules", []):
        if not isinstance(rule, dict):
            continue
        cat = rule.get("category")
        action = rule.get("action")
        if cat in _STRICT_BLOCK_CATEGORIES and action == "TOKENIZE":
            rule["action"] = "BLOCK"
            changed = True
    if not changed:
        return policy_text
    parsed.setdefault("name", "strict")
    return yaml.safe_dump(parsed, sort_keys=False, default_flow_style=False)


def run_init(*, industry: str, strict: bool, out: str) -> int:
    try:
        src = _shipped_path(industry)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    dst = Path(out).resolve()
    if dst.exists():
        print(
            f"error: refusing to overwrite existing {dst}. "
            f"Move or rename it first.",
            file=sys.stderr,
        )
        return 2
    text = src.read_text(encoding="utf-8")
    if strict:
        text = _apply_strict(text)
    dst.write_text(text, encoding="utf-8")
    print(f"wrote {dst}")
    if strict:
        print(
            "strict mode applied: TOKENIZE rules on private_key / cloud_api_key / "
            "secret / database_url / jwt promoted to BLOCK."
        )
    print(
        f"point the proxy at this policy with "
        f"PROMPTGUARD_POLICY_FILE={dst} docker compose up -d"
    )
    return 0
