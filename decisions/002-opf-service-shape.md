# DEC-002: OPF as a separate FastAPI service container

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** Day 1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

The locked architecture (research-notes section 6) specifies OPF as a default detector alongside Presidio. The Day-1 deliverable lists "OPF as a local model server (HF Transformers, CPU mode default, GPU optional)" packaged via `docker-compose`.

OPF was released 2026-04-22 by OpenAI under Apache 2.0. There is no pre-built first-party container at the time of writing. Two integration options:

1. Import `transformers` and `torch` directly into the proxy process, load the model in-process.
2. Run OPF as its own service the proxy talks to over HTTP.

Both are technically Apache-2.0-compatible.

## Options considered

### Option 1: In-process import in the proxy
- Pros: One fewer container, simpler topology, no HTTP hop.
- Cons:
  - The proxy now has a hard dep on torch (~700MB) and transformers (~150MB). Anyone running the proxy is forced into that footprint.
  - Coupling the proxy lifecycle to a 3GB model load means proxy startup is 30-60s+.
  - GPU upgrade path forces the *proxy* to be CUDA-aware, which is the wrong layering: the proxy is a tiny stateful piece of HTTP routing logic.
  - Hot-reloading the proxy code means re-loading the model.

### Option 2: Separate FastAPI service container (chosen)
- Pros:
  - Proxy stays slim (httpx + pydantic + structlog).
  - Symmetric with Presidio: both are HTTP-spoken detector services.
  - GPU is a concern of one container, not the proxy.
  - Model load decoupled from proxy lifecycle.
  - Easier to swap detector implementations behind the same wire shape.
- Cons:
  - One extra container. One extra HTTP hop per detection (~ms over loopback).

### Option 3: gRPC service
- Pros: Lower per-call overhead, streaming-friendly.
- Cons: Dev-time friction (proto compilation, reflection); HTTP/JSON is sufficient at v1 latency budgets.

## Decision

OPF runs as a separate FastAPI service container exposed at `:8081`. The proxy talks to it via HTTP over the docker-compose network.

The container has two health-related endpoints:
- `GET /health` — returns 200 once FastAPI is up. Used by the docker-compose healthcheck.
- `GET /ready` — returns 200 only once the model is loaded. Used by operators or tests that need to wait for warm state.

The model is loaded **lazily** on the first `/detect` call. This means container startup is fast (`docker compose up -d` returns in seconds), but the first detection on a cold container is slow while ~3GB pulls.

## Consequences

### Enables
- Proxy container stays small enough to ship as a developer-friendly default.
- GPU upgrade is a per-service concern (`OPF_DEVICE=cuda` env override).
- Future swap to a smaller PII model (or a remote inference endpoint) is one config flip away.

### Constrains
- One extra container in `docker compose up`.
- Contract becomes load-bearing: the OPF service's `/detect` JSON shape is now an interface and changes need a versioning story.

### Revisit if
- The HTTP hop shows up in the p95 latency budget (open question on a v1.1 latency benchmark).
- A pre-built OPF container with the same wire shape becomes available; we then swap the build for a pulled image.

## Implementation notes

- `src/promptguard/services/opf_service/server.py` is the FastAPI server. The transformers pipeline is loaded inside `_load_pipeline()` under a threading lock so concurrent first requests do not race.
- `Dockerfile` installs torch CPU wheels via `https://download.pytorch.org/whl/cpu` so the default image stays under ~2GB. GPU users override `TORCH_INDEX` via a build arg.
- `HF_HOME` and `TRANSFORMERS_CACHE` point at `/cache/huggingface`, which is a named docker volume so the model survives container restarts.
- The proxy-side adapter (`src/promptguard/detectors/opf.py`) reads `PROMPTGUARD_OPF_URL` from env, defaulting to `http://localhost:8081`.
