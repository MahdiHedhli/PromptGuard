"""Policy hot-reload: poll the policy file, swap in-place on change.

The reloader runs on a daemon thread. Every `interval_s` seconds it
stats the policy file. If the mtime is newer than the last successful
load:

  1. Re-parse via `LocalYAMLPolicy` (full schema validation).
  2. Re-probe detector readiness via `build_pipeline_from_policy`. If
     the new policy enables OPF, the OPF service must be ready or the
     reload is rejected and the old policy continues to apply.
  3. Atomically swap `Policy`, `DetectionPipeline`, and `ActionEngine`
     references on the hook. Python attribute assignment is atomic,
     so in-flight requests finish with the old refs and the next
     request sees the new ones. The `TokenMap` is preserved across
     reloads so existing conversations keep their token-to-original
     mappings.

Failure modes that keep the old policy:
  * YAML parse error or schema violation: caller sees the schema error
    in logs; no live policy change.
  * OPF unreachable (when the new policy enables it): we refuse to
    activate. This mirrors the DEC-009 startup hard-fail at runtime.
  * Filesystem error reading the file: skip this poll cycle.

Reloader is opt-in via `PROMPTGUARD_POLICY_RELOAD_INTERVAL_S`. Setting
the value to 0 (the default) disables polling. Production deployments
that want hot reload set it to e.g. `2`.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from promptguard.proxy.litellm_hooks import PromptGuardHook

from promptguard.actions import ActionEngine
from promptguard.core.pipeline_factory import (
    DetectorUnavailableError,
    build_pipeline_from_policy,
)
from promptguard.policies.local_yaml import LocalYAMLPolicy, PolicySchemaError

logger = logging.getLogger("promptguard.policy_reloader")


class PolicyReloader:
    """Watch a policy file; swap into the hook on validated change."""

    def __init__(
        self,
        hook: "PromptGuardHook",
        policy_file: str | Path,
        interval_s: float = 2.0,
    ) -> None:
        self._hook = hook
        self._policy_file = Path(policy_file)
        self._interval = interval_s
        self._mtime: float = 0.0
        try:
            self._mtime = self._policy_file.stat().st_mtime
        except FileNotFoundError:
            logger.warning(
                "policy file not present at reloader init: %s; "
                "will pick up once it appears",
                self._policy_file,
            )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="promptguard-policy-reloader",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "policy reloader watching %s every %.1fs",
            self._policy_file,
            self._interval,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval * 2)
            self._thread = None

    def check_once(self) -> bool:
        """Run one poll cycle. Returns True iff a swap took place.

        Public for tests; the background thread calls this on a timer.
        """
        try:
            mtime = self._policy_file.stat().st_mtime
        except (FileNotFoundError, PermissionError) as exc:
            logger.debug("policy file stat failed: %r", exc)
            return False
        if mtime <= self._mtime:
            return False

        try:
            new_policy = LocalYAMLPolicy(self._policy_file).load()
        except PolicySchemaError as exc:
            logger.error(
                "policy reload rejected (schema): keeping previous policy. %s",
                exc,
            )
            self._mtime = mtime  # don't keep retrying the same broken file
            return False

        try:
            new_pipeline = build_pipeline_from_policy(new_policy)
        except DetectorUnavailableError as exc:
            logger.error(
                "policy reload rejected (detector unavailable): "
                "keeping previous policy. %s",
                exc,
            )
            self._mtime = mtime
            return False

        # Preserve the existing TokenMap so live conversations keep
        # their reverse mappings across the swap.
        new_engine = ActionEngine(new_policy, token_map=self._hook.token_map)
        self._hook._swap_policy(new_policy, new_pipeline, new_engine)
        self._mtime = mtime
        logger.info(
            "policy reloaded: name=%s version=%s detectors=%s",
            new_policy.name,
            new_policy.version,
            [d.name for d in new_pipeline.detectors],
        )
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self._interval)
            if self._stop.is_set():
                break
            try:
                self.check_once()
            except Exception:
                logger.exception("policy reloader poll cycle failed")


def reloader_from_env(hook: "PromptGuardHook") -> PolicyReloader | None:
    """Construct a reloader from env, or None if disabled.

    PROMPTGUARD_POLICY_RELOAD_INTERVAL_S: float seconds; 0 disables.
    PROMPTGUARD_POLICY_FILE: same env var the hook reads at startup.
    """
    interval_s = float(os.environ.get("PROMPTGUARD_POLICY_RELOAD_INTERVAL_S", "0"))
    if interval_s <= 0:
        return None
    policy_file = os.environ.get(
        "PROMPTGUARD_POLICY_FILE", "/app/policies/default.yaml"
    )
    return PolicyReloader(hook, policy_file, interval_s=interval_s)
