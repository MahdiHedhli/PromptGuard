# Mock Anthropic upstream. Used for integration testing only.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install "fastapi>=0.115" "uvicorn[standard]>=0.30" "pydantic>=2.7"

COPY server.py /app/server.py

EXPOSE 9099

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost:9099/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "9099"]
