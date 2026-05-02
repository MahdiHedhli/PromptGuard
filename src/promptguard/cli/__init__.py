"""PromptGuard CLI entry point.

Subcommands:

  promptguard doctor                Preflight checks for a deployable stack.
  promptguard init                  Copy a starter policy into the cwd.
  promptguard validate-policy       Schema-validate a policy YAML file.
  promptguard policy-diff           Show the behavioral delta between policies.

Run with `python -m promptguard.cli <subcommand>` or, after pyproject's
`[project.scripts]` entry is registered, just `promptguard <subcommand>`.
"""

from __future__ import annotations

import argparse
import sys

from promptguard.cli.doctor import run_doctor
from promptguard.cli.init import run_init
from promptguard.cli.policy_diff import run_policy_diff
from promptguard.cli.validate_policy import run_validate_policy


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptguard",
        description="PromptGuard operator CLI.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # doctor
    p_doctor = sub.add_parser(
        "doctor", help="Run preflight checks against the local environment."
    )
    p_doctor.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color in output."
    )

    # init
    p_init = sub.add_parser("init", help="Copy a starter policy into the cwd.")
    p_init.add_argument(
        "--industry",
        default="default",
        help="Which shipped policy template to copy (default, regex-only, pentest-engagement).",
    )
    p_init.add_argument(
        "--strict",
        action="store_true",
        help="Promote TOKENIZE rules to BLOCK on sensitive categories.",
    )
    p_init.add_argument(
        "--out",
        default="policy.yaml",
        help="Output path. Default: ./policy.yaml.",
    )

    # validate-policy
    p_validate = sub.add_parser(
        "validate-policy", help="Schema-validate a policy YAML file."
    )
    p_validate.add_argument("path", help="Path to the policy YAML file.")

    # policy-diff
    p_diff = sub.add_parser(
        "policy-diff", help="Show behavioral delta between two policies."
    )
    p_diff.add_argument("old", help="Path to the older policy YAML.")
    p_diff.add_argument("new", help="Path to the newer policy YAML.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.cmd == "doctor":
        return run_doctor(no_color=args.no_color)
    if args.cmd == "init":
        return run_init(industry=args.industry, strict=args.strict, out=args.out)
    if args.cmd == "validate-policy":
        return run_validate_policy(path=args.path)
    if args.cmd == "policy-diff":
        return run_policy_diff(old=args.old, new=args.new)
    parser.error(f"unknown command: {args.cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
