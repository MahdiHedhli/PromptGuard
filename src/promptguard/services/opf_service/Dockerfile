# OPF service Dockerfile.
# Base on slim Python; install torch CPU wheels (no CUDA toolkit) so default
# image stays under 2GB. GPU users override with `--build-arg TORCH_INDEX=...`.

FROM python:3.11-slim AS base

ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/cache/huggingface \
    TRANSFORMERS_CACHE=/cache/huggingface

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install torch from the CPU index first (smallest wheel set), then the rest.
RUN pip install --index-url ${TORCH_INDEX} "torch>=2.3"
RUN pip install \
        "fastapi>=0.115" \
        "uvicorn[standard]>=0.30" \
        "transformers>=4.44" \
        "pydantic>=2.7"

COPY server.py /app/server.py

EXPOSE 8081

# Healthcheck reports server-up only. /ready is a separate endpoint
# operators can poll for model-loaded status.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8081/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8081"]
