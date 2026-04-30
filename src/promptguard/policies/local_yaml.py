"""LocalYAMLPolicy: reads a policy YAML from disk.

Schema (see policies/default.yaml for the canonical example):

    name: default
    version: "1"
    audit_only: false
    rules:
      - category: private_key
        action: BLOCK
      - category: email
        action: MASK
        min_confidence: 0.6
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from promptguard.core.policy import Action, Category, Policy, PolicyRule


class LocalYAMLPolicy:
    name: str = "local_yaml"

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Policy:
        if not self._path.is_file():
            raise FileNotFoundError(f"policy file not found: {self._path}")
        with self._path.open("r", encoding="utf-8") as fh:
            raw: Any = yaml.safe_load(fh)
        if not isinstance(raw, dict):
            raise ValueError(f"policy YAML must be a mapping at top level: {self._path}")

        rules_raw = raw.get("rules", [])
        if not isinstance(rules_raw, list):
            raise ValueError(f"policy 'rules' must be a list: {self._path}")

        rules: list[PolicyRule] = []
        for entry in rules_raw:
            if not isinstance(entry, dict):
                raise ValueError(f"each rule must be a mapping: {entry!r}")
            rules.append(
                PolicyRule(
                    category=Category(entry["category"]),
                    action=Action(entry["action"]),
                    min_confidence=float(entry.get("min_confidence", 0.0)),
                )
            )

        return Policy(
            name=str(raw.get("name", self._path.stem)),
            version=str(raw.get("version", "1")),
            audit_only=bool(raw.get("audit_only", False)),
            rules=rules,
        )
