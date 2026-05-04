# DEC-016: Policy hot-reload via opt-in mtime polling

**Date:** 2026-05-03
**Status:** Accepted
**Phase:** v1 (policy config polish)
**Author:** MahdiHedhli

---

## Context

the v1 plan lists policy hot-reload as a nice-to-have with a 4-hour
timebox. The motivation: operators iterating on a policy YAML want to
see changes apply without restarting the proxy and disrupting in-flight
conversations. Restart also resets the per-conversation TokenMap, so
any conversation mid-flight loses its reverse mappings on reload.

A hot-reload must:

1. Validate the new policy before swapping. A broken file must not take
   down the proxy.
2. Re-probe detector readiness if the new policy changes detector
   toggles. The DEC-009 OPF hard-fail guarantee at startup must hold
   at runtime too.
3. Swap atomically so in-flight requests finish with consistent state.
4. Preserve the TokenMap across swaps so live conversations keep their
   reverse mappings.

## Options considered

### Option 1: Filesystem watcher via `watchdog`
- Pros: Event-driven, near-instant pick-up of changes.
- Cons: Adds a dep (BSD-3, Apache-compatible). watchdog has known
  quirks across docker bind-mount semantics on macOS Docker Desktop;
  inotify events do not always fire reliably on shared volumes.

### Option 2: Stdlib mtime polling on a daemon thread (chosen)
- Pros: Zero deps. Predictable across docker bind-mount setups.
  Polling interval is tunable; default 2s is plenty fast for an
  operator workflow ("save the file, send a request, see the new
  policy apply"). Daemon thread cannot block process exit.
- Cons: Up to `interval_s` latency between save and pick-up. Every
  poll touches the filesystem.

### Option 3: SIGHUP handler that triggers reload
- Pros: Zero deps; widely understood Unix idiom.
- Cons: Requires the operator to find the proxy PID and kill -HUP it,
  a workflow that does not match "save the file in your editor".

## Decision

Stdlib mtime polling on a daemon thread, opt-in via env var. Settings:

```
PROMPTGUARD_POLICY_RELOAD_INTERVAL_S    float seconds; 0 disables. Default 0.
PROMPTGUARD_POLICY_FILE                 path to YAML; same as startup.
```

Reload protocol:

1. On every poll cycle, `os.stat(policy_file).st_mtime`. If unchanged
   since last successful load, skip.
2. Re-parse via `LocalYAMLPolicy(...).load()`. On `PolicySchemaError`,
   log the full multi-line error message (operator can see line +
   column + field path) and keep the old policy active. Update the
   recorded mtime so we do not retry the broken file every cycle.
3. Re-probe detector readiness via `build_pipeline_from_policy(...)`.
   On `DetectorUnavailableError`, log and keep the old policy. This
   is the runtime equivalent of the DEC-009 startup hard-fail.
4. Construct a new `ActionEngine(new_policy, token_map=existing_map)`.
   The TokenMap reference is the same object the previous engine held,
   so live conversations keep their reverse mappings.
5. Atomically swap the hook's `_policy`, `_pipeline`, `_engine`
   references. Python attribute assignment is atomic; in-flight
   `_inspect` calls that already read the old refs finish with them.

Default is OFF so the v1 packaging-polish target ("docker compose up,
done") does not pay even the modest CPU cost of polling. Operators
that want hot reload set the interval explicitly.

## Consequences

### Enables
- Edit a policy file, save, hit refresh; the next request applies the
  new policy. Up to `interval_s` latency between save and pick-up.
- TokenMap survives the swap; mid-flight conversations keep their
  reverse mappings.
- Misconfigured edits are rejected loudly without taking the proxy
  down.

### Constrains
- A reload that flips a detector toggle from off to on can stall the
  reload until the detector is ready (e.g. OPF model loaded). Within
  the existing fail-loud semantics: if it cannot activate, it logs and
  keeps the old policy.
- Polling has a worst-case `interval_s` latency. 2s default is fine for
  an operator workflow; a CI-style use case ("change file, run test
  immediately") may want 0.5s.

### Revisit if
- Operators report needing event-driven pick-up. At that point we add
  watchdog as an optional extra (`pip install promptguard[watch]`).
- A reload race shows up under contention (very unlikely given the
  atomic-attr-assignment design, but worth a stress test if reported).

## Implementation notes

- `src/promptguard/proxy/policy_reloader.py` contains the `PolicyReloader`
  class and the `reloader_from_env` factory.
- The hook's `_swap_policy(policy, pipeline, engine)` method is the
  one and only place the references are reassigned. Tests assert
  TokenMap identity is preserved via `hook._engine.token_map is
  hook.token_map`.
- 6 unit tests in `tests/unit/test_policy_reloader.py`: mtime change,
  unchanged mtime, schema-error rejection, OPF-unavailable rejection,
  TokenMap survival, background-thread smoke test.
