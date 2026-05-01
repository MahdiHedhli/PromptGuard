"""ICAPPolicy: PoC stub for ICAP (RFC 3507) integration.

v1 ships a sample ICAP response fixture (`tests/fixtures/icap/`) so the
parsing path is exercised against the wire shape an ICAP server would
return. Real Symantec / Forcepoint / Trellix integration lands in v1.1.

# Translation contract

The ICAP response format used here is a PromptGuard-flavored variant
documented in `docs/adapters.md`:

  ICAP/1.0 200 OK
  Server: ...
  Content-Type: application/x-promptguard-rules+text
  Content-Length: ...

  # comments OK
  <category>\\t<action>\\t<min_confidence>
  <category>\\t<action>\\t<min_confidence>
  ...

Vendor-specific bodies (Symantec, Forcepoint, Trellix) translate to this
shape inside their respective v1.1 adapter implementations; the v1
parser handles the PromptGuard intermediate format only.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from promptguard.core.policy import Action, Category, DetectorConfig, Policy, PolicyRule
from promptguard.policies.base import PolicyAdapter
from promptguard.policies.local_yaml import PolicySchemaError


class ICAPPolicy(PolicyAdapter):
    name: ClassVar[str] = "icap"

    def __init__(self, fixture_path: str | Path) -> None:
        # v1: read a file containing a recorded ICAP response. v1.1 will
        # accept a server URL and perform the OPTIONS / RESPMOD round-trip.
        self._path = Path(fixture_path)

    def load(self) -> Policy:
        if not self._path.is_file():
            raise FileNotFoundError(f"ICAP fixture not found: {self._path}")
        raw = self._path.read_text(encoding="utf-8")

        # Skip ICAP headers; body starts after the first blank line.
        try:
            _headers, body = raw.split("\n\n", 1)
        except ValueError as exc:
            raise PolicySchemaError(
                f"ICAP fixture missing header / body separator: {self._path}"
            ) from exc

        rules = self._parse_rule_body(body)
        return Policy(
            name=f"icap-{self._path.stem}",
            version="1",
            audit_only=False,
            detectors=DetectorConfig(),
            rules=rules,
        )

    @staticmethod
    def _parse_rule_body(body: str) -> list[PolicyRule]:
        rules: list[PolicyRule] = []
        seen_categories: set[Category] = set()
        for line_num, raw_line in enumerate(body.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                raise PolicySchemaError(
                    f"ICAP body line {line_num}: expected tab-separated "
                    f"<category>\\t<action>[\\t<min_confidence>], got {raw_line!r}"
                )
            category_str = parts[0].strip()
            action_str = parts[1].strip()
            min_conf_str = parts[2].strip() if len(parts) > 2 else "0.0"
            try:
                category = Category(category_str)
            except ValueError as exc:
                raise PolicySchemaError(
                    f"ICAP body line {line_num}: unknown category "
                    f"{category_str!r}: {exc}"
                ) from exc
            try:
                action = Action(action_str)
            except ValueError as exc:
                raise PolicySchemaError(
                    f"ICAP body line {line_num}: unknown action "
                    f"{action_str!r}: {exc}"
                ) from exc
            try:
                min_conf = float(min_conf_str)
            except ValueError as exc:
                raise PolicySchemaError(
                    f"ICAP body line {line_num}: min_confidence "
                    f"{min_conf_str!r} is not a float: {exc}"
                ) from exc
            min_conf = max(0.0, min(1.0, min_conf))
            if category in seen_categories:
                raise PolicySchemaError(
                    f"ICAP body line {line_num}: category {category.value} "
                    "appears twice; one rule per category"
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
