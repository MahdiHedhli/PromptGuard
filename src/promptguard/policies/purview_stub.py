"""PurviewDLPPolicy: PoC stub for Microsoft Purview DLP integration.

v1 ships a sample SIT-export fixture (`tests/fixtures/purview/`) so the
import path is exercised against realistic input shapes. Real Graph API
auth + classifier pull arrives in v1.1; the parsing / translation logic
in this module is real and tested.

# Translation contract

A Purview SIT export is JSON with `informationTypes[]`. Each entry
carries a `promptguardCategory` and a `recommendedAction`, plus optional
`minConfidence`. The translation:

  - `promptguardCategory` -> `Category` enum (string matched, error if unknown)
  - `recommendedAction`   -> `Action` enum (string matched, error if unknown)
  - `minConfidence`       -> `PolicyRule.min_confidence` (clamped to [0, 1])

Top-level fields:
  - `policyName`    -> `Policy.name`
  - `policyVersion` -> `Policy.version`

Detector toggles default to v1 shipping posture (regex/opf/presidio on,
llm_judge off). v1.1 may add Purview-side hints for which detectors to
enable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from promptguard.core.policy import Action, Category, DetectorConfig, Policy, PolicyRule
from promptguard.policies.base import PolicyAdapter
from promptguard.policies.local_yaml import PolicySchemaError


class PurviewDLPPolicy(PolicyAdapter):
    name: ClassVar[str] = "purview_dlp"

    def __init__(self, sample_export_path: str | Path) -> None:
        # v1: file path required. v1.1 will add a tenant_id constructor
        # that fetches via Graph API; for now an explicit path is the
        # entire interface.
        self._path = Path(sample_export_path)

    def load(self) -> Policy:
        if not self._path.is_file():
            raise FileNotFoundError(f"Purview SIT export not found: {self._path}")
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PolicySchemaError(
                f"Purview SIT export is not valid JSON: {self._path}\n  {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise PolicySchemaError(
                f"Purview SIT export must be a JSON object at top level: {self._path}"
            )

        rules = self._translate_information_types(raw.get("informationTypes", []))
        return Policy(
            name=str(raw.get("policyName", self._path.stem)),
            version=str(raw.get("policyVersion", "1")),
            audit_only=False,
            detectors=DetectorConfig(),  # default v1 posture
            rules=rules,
        )

    @staticmethod
    def _translate_information_types(
        info_types: list[Any],
    ) -> list[PolicyRule]:
        if not isinstance(info_types, list):
            raise PolicySchemaError(
                "Purview SIT export 'informationTypes' must be a list"
            )
        rules: list[PolicyRule] = []
        seen_categories: set[Category] = set()
        for i, item in enumerate(info_types):
            if not isinstance(item, dict):
                raise PolicySchemaError(
                    f"informationTypes[{i}] must be an object, got {type(item).__name__}"
                )
            try:
                category = Category(item["promptguardCategory"])
            except (KeyError, ValueError) as exc:
                raise PolicySchemaError(
                    f"informationTypes[{i}] missing or invalid 'promptguardCategory': "
                    f"{item.get('promptguardCategory')!r} (err: {exc})"
                ) from exc
            try:
                action = Action(item["recommendedAction"])
            except (KeyError, ValueError) as exc:
                raise PolicySchemaError(
                    f"informationTypes[{i}] missing or invalid 'recommendedAction': "
                    f"{item.get('recommendedAction')!r} (err: {exc})"
                ) from exc
            min_conf = float(item.get("minConfidence", 0.0))
            min_conf = max(0.0, min(1.0, min_conf))
            if category in seen_categories:
                raise PolicySchemaError(
                    f"informationTypes[{i}] duplicates category {category.value}; "
                    "Purview translations must be 1:1 to PromptGuard categories"
                )
            seen_categories.add(category)
            rules.append(
                PolicyRule(
                    category=category,
                    action=action,
                    min_confidence=min_conf,
                )
            )
        return rules
