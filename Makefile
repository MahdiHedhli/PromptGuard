# PromptGuard top-level operator targets.
#
# Run `make help` for the canonical list. Targets are designed so a fresh
# clone goes from zero to a passing release-check with two commands:
#
#   uv sync --extra dev
#   make release-check
#
# All targets honor the `PYTHON` env var (default: `uv run python`) and
# the `PROMPTGUARD_LITELLM_PORT` env var (default: 4000).

PYTHON ?= uv run python
PYTEST ?= uv run pytest
PROMPTGUARD_LITELLM_PORT ?= 4000

.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

.PHONY: help
help:
	@echo "PromptGuard make targets:"
	@echo ""
	@echo "  test                 Run the unit suite (no docker)."
	@echo "  test-integration     Run integration tests against a running stack."
	@echo "  smoke                Bring stack up, run integration tests, tear down."
	@echo "  benchmark            Run detection + latency benchmarks."
	@echo "  doctor               Run promptguard doctor preflight checks."
	@echo "  release-check        Full release readiness suite."
	@echo "  clean                Remove build artifacts, __pycache__, caches."
	@echo ""
	@echo "  mitm-up              Bring up the MITM verification harness."
	@echo "  mitm-down            Tear down the MITM verification harness."
	@echo "  mitm-scrub           Wipe MITM captures + CA. (destructive)"

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

.PHONY: test
test:
	$(PYTEST) -q

.PHONY: test-integration
test-integration:
	$(PYTEST) -q -m integration

.PHONY: smoke
smoke:
	@echo ">>> building docker stack (picks up source changes)"
	docker compose build
	@echo ">>> bringing up docker stack"
	docker compose up -d --wait
	@echo ">>> running docker-marked integration tests"
	-$(PYTEST) -q -m docker
	@echo ">>> tearing down docker stack"
	docker compose down

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

.PHONY: benchmark
benchmark:
	@echo ">>> detection benchmark"
	$(PYTHON) benchmarks/run_detection_benchmarks.py
	@echo ">>> latency matrix"
	$(PYTHON) benchmarks/run_latency_matrix.py

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

.PHONY: doctor
doctor:
	$(PYTHON) -m promptguard.cli doctor

# ---------------------------------------------------------------------------
# Release readiness
# ---------------------------------------------------------------------------

.PHONY: release-check
release-check:
	bash scripts/release-check.sh

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

.PHONY: clean
clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	find . -type d -name .ruff_cache -prune -exec rm -rf {} +
	find . -type d -name .mypy_cache -prune -exec rm -rf {} +

# ---------------------------------------------------------------------------
# MITM verification harness (delegates to the harness's own Makefile)
# ---------------------------------------------------------------------------

.PHONY: mitm-up mitm-down mitm-scrub mitm-test mitm-logs
mitm-up:
	$(MAKE) -C tools/mitm-verify up

mitm-down:
	$(MAKE) -C tools/mitm-verify down

mitm-scrub:
	$(MAKE) -C tools/mitm-verify scrub

mitm-test:
	$(MAKE) -C tools/mitm-verify test

mitm-logs:
	$(MAKE) -C tools/mitm-verify logs
