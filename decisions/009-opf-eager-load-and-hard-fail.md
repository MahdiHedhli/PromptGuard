# DEC-009: Eager-load OPF model at service startup; hard-fail proxy if /ready not 200

**Date:** 2026-05-01
**Status:** Accepted
**Phase:** v1 (action engine + LiteLLM hook)
**Author:** MahdiHedhli

---

## Context

v1 directive: if a policy enables OPF and OPF is not
available, hard-fail with a clear, actionable error. PromptGuard's
threat-model promise is "PII never leaves the host"; silently degrading
to "OPF disabled" breaks that promise without operator awareness.

v1 (DEC-002) intentionally shipped lazy model loading on first
`/detect` call, with `/health` reporting server-up and `/ready` reporting
model-loaded. The lazy approach kept `docker compose up -d --wait` fast.

The interaction: under lazy loading, `/ready` returns 503 until something
calls `/detect`. The proxy probes `/ready` at startup. If nobody ever
calls `/detect`, `/ready` stays 503 forever and the proxy refuses to
start. The lazy + hard-fail combination is unbootable.

## Options considered

### Option 1: Keep lazy; have the proxy probe `/detect` instead of `/ready`
- Pros: No service change.
- Cons: A startup probe with synthetic text would (a) consume model load
  time on the proxy startup path, (b) tightly couple the proxy to a
  specific request shape, (c) leak random startup text into operator
  logs. Wrong shape.

### Option 2: Eager load at OPF service startup (chosen)
- Pros: `/ready` becomes meaningful: "the model loaded successfully" or
  "the load failed loudly with an error message". The proxy's hard-fail
  check works as specified. If the HF model path is wrong, the
  operator sees the failure within seconds of `docker compose up`, not
  on the first user request.
- Cons: Container takes longer to become "fully ready" (the load is
  ~3GB and a few seconds CPU). `/health` (server-up) still returns
  immediately so docker compose's healthcheck does not block on it.

### Option 3: Eager load OPF AND retry-with-backoff in the proxy
- Pros: Tolerates slow downloads.
- Cons: Hides startup failures behind retries, the failure mode the v1
  directive explicitly rules out.

## Decision

Eager load. On OPF service startup we kick off a background thread that
invokes `_load_pipeline()`. `/health` returns 200 immediately (server-up).
`/ready` returns 200 once the load completes successfully, 503 with a
JSON detail otherwise (`{"status": "loading"}` or
`{"status": "load_failed", "error": "..."}`).

The proxy's `build_pipeline_from_policy()` probes `/ready` with a 5-second
timeout when OPF is enabled. On non-200 the proxy raises
`DetectorUnavailableError` with the exact message from the v1 plan:

```
OPF model not available at $url. Refusing to start pipeline.
To run without OPF detection, set detectors.opf.enabled = false in your
policy file.
```

A `policies/regex-only.yaml` ships as the documented escape hatch for
operators who want to run without OPF (offline installs, restricted
egress).

`OPF_EAGER_LOAD=0` disables eager load for unit tests of the server.

## Consequences

### Enables
- Hard-fail works as specified. If the OPF model is misconfigured or
  unreachable, the operator sees it immediately at `docker compose up`.
- `/ready` is now a real liveness signal that operators can poll.
- Regex-only mode is documented and tested.

### Constrains
- OPF container uses ~3GB of RAM steady-state once the model is loaded.
  v1.1 should explore quantized variants for memory-constrained hosts.
- The 5-second timeout on `/ready` may need to be tunable; in practice
  cold model load on CPU can take 30 seconds or more on first download.
  The proxy fails-loud rather than hanging, which is correct behavior;
  operators retry once the OPF container reports ready.

### Revisit if
- We add a quantized OPF variant that loads in <5s on CPU.
- We move the proxy probe to a polling loop (60s with backoff). At that
  point we accept slower startup in exchange for tolerating slow first
  downloads.

## Implementation notes

- Eager load in `src/promptguard/services/opf_service/server.py`
  `_start_eager_load()` (FastAPI startup event).
- Hard-fail in `src/promptguard/core/pipeline_factory.py`
  `build_pipeline_from_policy()`, behind `skip_opf_readiness_check=False`.
- Tests in `tests/unit/test_pipeline_factory.py` cover unreachable
  service, ready service, OPF disabled, zero-detectors, and LLM-judge
  enabled (also a hard-fail because the v1.1 detector is not shipped).
