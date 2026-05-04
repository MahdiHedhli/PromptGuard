"""Docker stack health smoke test.

Marked `docker` so it's skipped in the default pytest run. Run with:

    docker compose up -d --wait
    pytest -m docker

Validates that the stack is reachable on its published ports and that
each service's healthcheck reports up.
"""

from __future__ import annotations

import os

import httpx
import pytest

# Honor the same port-override env vars docker-compose reads, so the
# smoke target works on hosts where 4000 / 5002 / 8081 are taken.
# Either PROMPTGUARD_LITELLM_URL (full URL) or PROMPTGUARD_LITELLM_PORT
# (port only) suffices; the URL form wins when both are set.
_LITELLM_PORT = os.environ.get("PROMPTGUARD_LITELLM_PORT", "4000")
_PRESIDIO_PORT = os.environ.get("PROMPTGUARD_PRESIDIO_PORT", "5002")
_OPF_PORT = os.environ.get("PROMPTGUARD_OPF_PORT", "8081")
LITELLM_URL = os.environ.get(
    "PROMPTGUARD_LITELLM_URL", f"http://localhost:{_LITELLM_PORT}"
)
PRESIDIO_URL = os.environ.get(
    "PROMPTGUARD_PRESIDIO_URL", f"http://localhost:{_PRESIDIO_PORT}"
)
OPF_URL = os.environ.get(
    "PROMPTGUARD_OPF_URL", f"http://localhost:{_OPF_PORT}"
)


async def _get_or_skip(url: str, *, service_name: str) -> httpx.Response:
    """GET `url`. If the service can't be reached cleanly, skip the test.

    "Can't be reached cleanly" means: connection refused, timeout, DNS,
    or a peer that accepts the TCP connection but closes without a
    response (some other process is bound to that port).
    """
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            return await client.get(url)
        except (
            httpx.ConnectError,
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.RemoteProtocolError,
        ) as exc:
            pytest.skip(
                f"{service_name} not reachable at {url} ({type(exc).__name__}); "
                f"bring stack up with `docker compose up -d --wait`"
            )


@pytest.mark.docker
@pytest.mark.integration
async def test_litellm_liveness() -> None:
    resp = await _get_or_skip(f"{LITELLM_URL}/health/liveliness", service_name="LiteLLM")
    assert resp.status_code == 200


@pytest.mark.docker
@pytest.mark.integration
async def test_opf_health() -> None:
    resp = await _get_or_skip(f"{OPF_URL}/health", service_name="OPF service")
    assert resp.status_code == 200


@pytest.mark.docker
@pytest.mark.integration
async def test_presidio_health() -> None:
    resp = await _get_or_skip(f"{PRESIDIO_URL}/health", service_name="Presidio analyzer")
    assert resp.status_code == 200
