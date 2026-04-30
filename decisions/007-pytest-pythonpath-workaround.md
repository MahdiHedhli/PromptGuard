# DEC-007: Set `pythonpath = ["src"]` in pytest config to work around editable-install fragility

**Date:** 2026-04-30
**Status:** Accepted
**Phase:** Day 1 (scaffold)
**Author:** Claude Code (autonomous)

---

## Context

After `uv sync --extra dev --extra proxy`, running `pytest` (either via `uv run pytest` or `.venv/bin/pytest`) intermittently fails with `ModuleNotFoundError: No module named 'promptguard'`, even though `uv pip list` reports the package as installed in editable mode.

Investigation:

1. The hatchling editable backend writes `.venv/lib/python3.11/site-packages/_editable_impl_promptguard.pth`. Its content is the absolute path to `src/`.
2. CPython 3.11's `site.py` (and 3.12+) **skips** any `.pth` file whose name begins with `_` or `.`. Verbose import logs show: `Skipping hidden .pth file: '.../site-packages/_editable_impl_promptguard.pth'`.
3. As a result the `src/` path is never added to `sys.path` from the `.pth`.
4. `uv run` *sometimes* works around this by injecting `src/` into `sys.path` from its own project detection, but the trigger is fragile: a subsequent `uv sync` can leave the venv in a state where `uv run python -c "import promptguard"` fails.

This is not a uv-only problem; it is the hatchling editable plugin colliding with site.py's hidden-pth filter.

## Options considered

### Option 1: Switch build backend to setuptools
- Pros: Setuptools' editable plugin writes `__editable__.<pkg>-<ver>.pth`, which does not start with underscore and is processed by site.py.
- Cons: Larger change; setuptools brings more historical baggage; we'd have to express our `src/` layout via `[tool.setuptools.packages.find]` plus other config.

### Option 2: Add `pythonpath = ["src"]` to pytest config (chosen)
- Pros: Tiny change. Pytest always finds the source regardless of editable-install state. Works under both `uv run pytest` and `.venv/bin/pytest`.
- Cons: Only fixes pytest. `python -c "import promptguard"` outside pytest still requires `uv run` (which works most of the time) or a manual `PYTHONPATH=src`.

### Option 3: Carry a post-install hook that renames the `.pth` file
- Pros: Fixes the editable install for everyone.
- Cons: Hacky; would need a custom hatch plugin or a `tool.uv.build-constraint`-style override; brittle across uv/hatchling upgrades.

### Option 4: Wait for the upstream fix
- Hatchling has open discussion about renaming the editable `.pth`. Upstream fix would resolve this, but the timeline is unknown.

## Decision

Option 2 for now. Add `pythonpath = ["src"]` under `[tool.pytest.ini_options]` in `pyproject.toml`. The CI / local-dev test path is the one we cannot afford to be flaky.

For interactive `python -c` usage, contributors should use `uv run python` (which works after a fresh `uv sync` in most cases) or set `PYTHONPATH=src` themselves. README will document this.

Revisit by switching to setuptools (Option 1) if the workaround becomes painful or if a contributor reports a tooling break that this workaround does not cover.

## Consequences

### Enables
- Reliable `pytest` runs across `uv run`, `.venv/bin/pytest`, and (in CI) plain `pytest`.
- No build-backend churn.

### Constrains
- `pythonpath` in pytest config is a soft commitment to `src/` layout; we keep it.
- Anyone running the package outside pytest needs the editable install to actually work; if they hit the same skip, we tell them to use `uv run` or set `PYTHONPATH=src`.

### Revisit if
- Hatchling renames its editable `.pth` to a non-underscore name.
- `python -c` usage outside `uv run` becomes a frequent contributor pain point — at that point switch to setuptools backend.

## Implementation notes

- Verbose import diagnostics: `.venv/bin/python -v -c "import promptguard" 2>&1 | grep pth` shows the skip explicitly.
- The `pythonpath` config landed in `pyproject.toml` under `[tool.pytest.ini_options]`. No other change required.
