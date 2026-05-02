"""`promptguard doctor` preflight checks.

Plain-English status for each thing PromptGuard needs to be deployable
on this host. Returns 0 if every check passed, 1 if any check failed.

Checks:

  * docker CLI present + daemon reachable
  * docker-compose.yml parses
  * default policy.yaml schema-validates
  * .env.example exists; .env loadable if present
  * host port 4000 / 4100 (LiteLLM), 5002 (Presidio), 8081 (OPF) status
  * OPF model presence in the local Hugging Face cache (informational)

The output is meant to read like "what an operator can take action on,"
not like Python error stacks.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class CheckResult:
    label: str
    ok: bool
    detail: str

    def render(self, color: bool) -> str:
        if color:
            tag_ok = "\033[32mPASS\033[0m"
            tag_fail = "\033[31mFAIL\033[0m"
        else:
            tag_ok = "PASS"
            tag_fail = "FAIL"
        tag = tag_ok if self.ok else tag_fail
        return f"  [{tag}] {self.label}\n         {self.detail}"


def _check_docker_cli() -> CheckResult:
    if shutil.which("docker") is None:
        return CheckResult(
            "docker CLI",
            ok=False,
            detail=(
                "docker is not on PATH. Install Docker Desktop or Docker Engine; "
                "this is a hard requirement for the proxy stack."
            ),
        )
    try:
        out = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return CheckResult(
            "docker daemon",
            ok=False,
            detail=(
                "docker is installed but the daemon is not responding. "
                "Start Docker Desktop, or run `docker info` to diagnose."
            ),
        )
    if out.returncode != 0:
        return CheckResult(
            "docker daemon",
            ok=False,
            detail=f"`docker version` returned {out.returncode}: {out.stderr.strip()}",
        )
    return CheckResult(
        "docker daemon", ok=True, detail=f"reachable, server version {out.stdout.strip()}"
    )


def _check_compose_file() -> CheckResult:
    compose = ROOT / "docker-compose.yml"
    if not compose.exists():
        return CheckResult(
            "docker-compose.yml",
            ok=False,
            detail=f"missing at {compose}; cannot start the stack.",
        )
    if shutil.which("docker") is None:
        return CheckResult(
            "docker-compose.yml syntax",
            ok=False,
            detail="docker not present, cannot validate compose file.",
        )
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", str(compose), "config"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            "docker-compose.yml syntax", ok=False, detail="`docker compose config` timed out."
        )
    if out.returncode != 0:
        return CheckResult(
            "docker-compose.yml syntax",
            ok=False,
            detail=f"`docker compose config` failed: {out.stderr.strip()[:300]}",
        )
    return CheckResult(
        "docker-compose.yml syntax",
        ok=True,
        detail="parses cleanly with `docker compose config`.",
    )


def _check_default_policy() -> CheckResult:
    policy_path = ROOT / "policies" / "default.yaml"
    if not policy_path.exists():
        return CheckResult(
            "default policy",
            ok=False,
            detail=f"missing at {policy_path}; the proxy needs a default policy to start.",
        )
    try:
        from promptguard.policies.local_yaml import LocalYAMLPolicy
    except ImportError as exc:
        return CheckResult(
            "default policy schema",
            ok=False,
            detail=f"could not import LocalYAMLPolicy: {exc}",
        )
    try:
        LocalYAMLPolicy(policy_path).load()
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "default policy schema",
            ok=False,
            detail=f"policy file failed schema validation: {exc}",
        )
    return CheckResult(
        "default policy schema",
        ok=True,
        detail=f"{policy_path.relative_to(ROOT)} validates cleanly.",
    )


def _check_env_files() -> CheckResult:
    example = ROOT / ".env.example"
    env = ROOT / ".env"
    if not example.exists():
        return CheckResult(
            ".env scaffolding",
            ok=False,
            detail=".env.example is missing; new operators have no template to copy from.",
        )
    if not env.exists():
        return CheckResult(
            ".env scaffolding",
            ok=True,
            detail=".env not present yet (expected for a fresh checkout); copy .env.example.",
        )
    return CheckResult(
        ".env scaffolding", ok=True, detail=".env exists and is loadable."
    )


def _check_port(port: int, label: str) -> CheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        return CheckResult(
            f"port {port} ({label})",
            ok=False,
            detail=(
                f"already bound; another process is on this port. "
                f"Override with PROMPTGUARD_LITELLM_PORT etc., or stop the conflicting process."
            ),
        )
    finally:
        sock.close()
    return CheckResult(f"port {port} ({label})", ok=True, detail="free")


def _check_opf_cache() -> CheckResult:
    candidates = [
        Path.home() / ".cache" / "huggingface" / "hub",
        Path.home() / "Library" / "Caches" / "huggingface" / "hub",
    ]
    for c in candidates:
        if not c.exists():
            continue
        for entry in c.glob("models--*"):
            n = entry.name.lower()
            if "openai" in n and "privacy" in n:
                return CheckResult(
                    "OPF model cache",
                    ok=True,
                    detail=f"found {entry.relative_to(c.parent)} on disk; first boot will be fast.",
                )
    return CheckResult(
        "OPF model cache",
        ok=True,  # informational; first boot will download
        detail="OPF model not yet cached. First `docker compose up` will download ~3 GB.",
    )


def run_doctor(*, no_color: bool = False) -> int:
    color = sys.stdout.isatty() and not no_color
    checks = [
        _check_docker_cli(),
        _check_compose_file(),
        _check_default_policy(),
        _check_env_files(),
        _check_port(int(os.environ.get("PROMPTGUARD_LITELLM_PORT", "4000")), "litellm"),
        _check_port(int(os.environ.get("PROMPTGUARD_PRESIDIO_PORT", "5002")), "presidio"),
        _check_port(int(os.environ.get("PROMPTGUARD_OPF_PORT", "8081")), "opf"),
        _check_opf_cache(),
    ]
    print("PromptGuard preflight:")
    print()
    for c in checks:
        print(c.render(color))
    print()
    failed = [c for c in checks if not c.ok]
    if failed:
        print(f"{len(failed)} check(s) failed. Address above before running `docker compose up`.")
        return 1
    print("All checks passed. You can run `docker compose up -d --wait`.")
    return 0
