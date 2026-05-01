# tools/mitm-verify/Makefile
# Convenience targets for the wire-verification harness (DEC-022).
#
# Run from the repo root or from this directory; the targets cd to the
# repo root automatically.

ROOT := $(shell git rev-parse --show-toplevel)
LITELLM_PORT ?= 4100
COMPOSE_FILES := -f docker-compose.yml -f tools/mitm-verify/docker-compose.mitm.yml

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "PromptGuard MITM verification harness"
	@echo ""
	@echo "Targets:"
	@echo "  up        Start the proxy stack with mitmproxy positioned"
	@echo "            between LiteLLM and the upstream provider."
	@echo "            Auto-generates the CA cert on first run."
	@echo "  test      Run all prompts under test-prompts/ through the"
	@echo "            proxy and produce a summary report under"
	@echo "            ./local/mitm-captures/summary-<timestamp>.md."
	@echo "  logs      Tail the mitmproxy container logs."
	@echo "  down      Stop the stack but keep ./local/ intact."
	@echo "  scrub     Wipe ./local/mitm-captures and ./local/mitm-ca."
	@echo ""
	@echo "Environment overrides:"
	@echo "  PROMPTGUARD_LITELLM_PORT (default $(LITELLM_PORT))"
	@echo "  PROMPTGUARD_TEST_MODEL   (default claude-sonnet-4-6)"

.PHONY: up
up:
	@echo "[mitm-verify] Bringing up stack with mitmproxy overlay..."
	@cd $(ROOT) && set -a && [ -f .env ] && . ./.env && set +a; \
	    PROMPTGUARD_LITELLM_PORT=$(LITELLM_PORT) \
	    docker compose $(COMPOSE_FILES) up -d --wait --wait-timeout 480
	@echo "[mitm-verify] Stack up. Captures will land in ./local/mitm-captures/"
	@echo "[mitm-verify] CA cert at ./local/mitm-ca/mitmproxy-ca-cert.pem"
	@echo "[mitm-verify] Test the wire: make test"

.PHONY: test
test:
	@cd $(ROOT) && tools/mitm-verify/run-test-suite.sh

.PHONY: logs
logs:
	@cd $(ROOT) && docker compose $(COMPOSE_FILES) logs -f mitmproxy

.PHONY: down
down:
	@echo "[mitm-verify] Stopping stack. Captures preserved in ./local/."
	@cd $(ROOT) && PROMPTGUARD_LITELLM_PORT=$(LITELLM_PORT) \
	    docker compose $(COMPOSE_FILES) down
	@echo "[mitm-verify] Stopped. To wipe captures: make scrub"

.PHONY: scrub
scrub:
	@echo "[mitm-verify] Wiping ./local/mitm-captures and ./local/mitm-ca..."
	@rm -rf $(ROOT)/local/mitm-captures $(ROOT)/local/mitm-ca
	@echo "[mitm-verify] Scrubbed."
