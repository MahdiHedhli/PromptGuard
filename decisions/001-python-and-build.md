# DEC-001: Python target, build system, and dependency manager

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** v1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

v1 needed a build/dep tooling choice before any code was written. The project has 14 calendar days and ships an open-source repo aimed at security engineers; tooling choices should be conventional, reproducible, and not create friction for contributors.

Constraints:
- Apache 2.0 deps only.
- Production-quality, not prototype-quality.
- "Deploy in minutes" UX.

## Options considered

### Option 1: pip + setuptools, no lockfile
- Pros: Lowest friction, vanilla Python.
- Cons: No lockfile, slow installs, no consistent dev experience.

### Option 2: Poetry
- Pros: Mature, lockfile, scripts.
- Cons: Slower than uv; another binary to install; PEP 621 support is partial.

### Option 3: uv + hatchling backend, PEP 621 pyproject
- Pros: Fastest installer (10x+), fully PEP 621, lockfile, drop-in for pip workflows, single binary. Already installed on dev machine.
- Cons: Newer tool, less industry inertia than Poetry.

### Option 4: PDM
- Pros: PEP 621 native, supports uv as resolver.
- Cons: Adds another layer; uv directly is simpler.

## Decision

**Python 3.11+** as the runtime floor. **uv** as the dependency manager and runner. **hatchling** as the build backend (PEP 517-compatible, declarative, well-supported).

Reasoning:
- Python 3.11 gives us `StrEnum`, `tomllib`, `Self`, and meaningful TaskGroup ergonomics. 3.12 adoption is high enough but 3.11 is the durable floor.
- uv collapses venv creation, pip install, and lockfile resolution into one tool that runs in seconds. It is Apache 2.0 + MIT licensed (Astral). Already installed on dev machine.
- Hatchling is the simplest PEP 517 backend; declarative `[tool.hatch.build.targets.wheel]` works without config gymnastics.

## Consequences

### Enables
- Single-command setup: `uv sync --extra dev`.
- Deterministic dev installs once `uv.lock` exists.
- Optional-extras grouping for proxy / opf-service / presidio so contributors can install only what they need.

### Constrains
- Contributors who refuse to install uv have to do `pip install -e .[dev]` manually. That is documented but suboptimal.
- Hatchling means Python build ergonomics are tied to its conventions.

### Revisit if
- A contributor reports that uv is a barrier on their platform.
- The project takes a hard dep on a Poetry-only tool.

## Implementation notes

- `pyproject.toml` declares optional extras: `proxy`, `opf-service`, `presidio`, `dev`.
- The OPF service container does *not* use uv at runtime; its Dockerfile uses pip directly because `python:3.11-slim` already has pip and we do not want to install a separate uv inside every container.
- pytest is configured with `asyncio_mode = "auto"` so async tests need no explicit marker.
