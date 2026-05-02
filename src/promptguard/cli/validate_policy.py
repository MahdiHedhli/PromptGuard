"""`promptguard validate-policy` schema validator.

Loads a policy YAML through `LocalYAMLPolicy.load()` and prints a
green PASS or a line-numbered error breakdown. Exit 0 on valid, 1
on invalid, 2 on missing file or other operator error.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pydantic import ValidationError

from promptguard.policies.local_yaml import LocalYAMLPolicy


def run_validate_policy(*, path: str) -> int:
    p = Path(path).resolve()
    if not p.exists():
        print(f"error: {p} does not exist", file=sys.stderr)
        return 2
    try:
        policy = LocalYAMLPolicy(p).load()
    except ValidationError as exc:
        print(f"INVALID  {p}")
        for err in exc.errors():
            loc = ".".join(str(part) for part in err["loc"])
            print(f"  {loc}: {err['msg']}")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"INVALID  {p}")
        print(f"  {type(exc).__name__}: {exc}")
        return 1
    print(f"VALID    {p}")
    print(
        f"         name={policy.name!r} version={policy.version!r} "
        f"rules={len(policy.rules)}"
    )
    return 0
