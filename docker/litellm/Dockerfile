# Custom LiteLLM image bundling PromptGuard.
#
# We extend the upstream LiteLLM image so we get LiteLLM's full server
# environment, then pip-install the PromptGuard package and copy the
# handler module that exposes `proxy_handler_instance` for LiteLLM's
# `litellm_settings.callbacks` config.
#
# Install path:
#   /app/handler.py                       handler module reference
#   /app/policies/                        sample policies (mounted in compose)
#   site-packages/promptguard/            installed package

# Digest pin (Day-10 packaging polish).
# Pinning to a specific image digest rather than a floating `main-stable`
# tag so the v1 release behavior is reproducible. Operators can verify
# they have the same image with `docker image inspect <id> --format '{{.RepoDigests}}'`.
# To bump: `docker pull ghcr.io/berriai/litellm:main-stable` and replace
# the digest below with the resolved one from `docker images --digests`.
ARG LITELLM_DIGEST=sha256:6c82d338a60e7b273ae46bf1d8db814d2856ae010f96c44eeadde574d3893f76
FROM ghcr.io/berriai/litellm@${LITELLM_DIGEST}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build context is the repo root (see docker-compose.yml).
COPY pyproject.toml /tmp/pg/pyproject.toml
COPY README.md /tmp/pg/README.md
COPY LICENSE /tmp/pg/LICENSE
COPY NOTICE /tmp/pg/NOTICE
COPY src /tmp/pg/src

# Install only the runtime deps PromptGuard needs (no dev/proxy/opf-service
# extras because LiteLLM already bundles fastapi/uvicorn).
# Upstream LiteLLM image is uv-managed and does not ship pip in the venv.
# Install uv ourselves (it's <10MB) and use `uv pip install` for the bundle.
# Match the uv version pinned by the upstream image so its `.python-version`
# / `uv.lock` semantics stay consistent. Bumping uv risks a re-resolve.
RUN python -m ensurepip --upgrade \
 && python -m pip install --no-cache-dir "uv==0.10.9" \
 && uv pip install --no-cache-dir /tmp/pg \
 && rm -rf /tmp/pg

# Handler module that LiteLLM's `callbacks: handler.proxy_handler_instance`
# config points at. Lives at /app/handler.py inside the container.
COPY docker/litellm/handler.py /app/handler.py
