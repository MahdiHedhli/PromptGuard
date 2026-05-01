"""OPF service: thin FastAPI wrapper around `openai/privacy-filter`.

The HuggingFace token-classification pipeline is loaded lazily on the
first /detect request. This keeps container startup fast (the model is
~3GB and takes time to fetch). Health is reported via two endpoints:

    GET /health  -> 200 always, while the FastAPI server is up.
    GET /ready   -> 200 once the model has been loaded; 503 until then.

`docker-compose.yml` uses /health for the readiness probe so the stack
reports up immediately. Operators that want to wait for the model can
poll /ready.

Endpoint contract:

    POST /detect
    { "text": "..." }
    -> 200 { "detections": [
        { "label": "private_email", "start": 0, "end": 12,
          "score": 0.97, "text": "x@example.com" }, ...
    ]}
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("promptguard.opf_service")

MODEL_ID = os.environ.get("OPF_MODEL_ID", "openai/privacy-filter")
DEVICE = os.environ.get("OPF_DEVICE", "cpu")  # "cpu" or "cuda" or "cuda:0"
EAGER_LOAD = os.environ.get("OPF_EAGER_LOAD", "1") == "1"

_pipe: Any = None
_pipe_load_error: str | None = None
_lock = threading.Lock()
_load_thread: threading.Thread | None = None


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start an eager-load thread before uvicorn begins serving traffic.

    Replaces the deprecated `@app.on_event("startup")` API. The thread is
    daemonic so it cannot block process exit; failures are recorded in
    `_pipe_load_error` so `/ready` can surface them. We do NOT wait for
    the load to finish here, so `/health` returns 200 immediately and
    operators / probes that need the model loaded poll `/ready` instead.
    """
    global _load_thread
    if EAGER_LOAD and _load_thread is None:
        def _bg() -> None:
            try:
                _load_pipeline()
            except Exception:
                logger.exception("eager OPF model load failed")

        _load_thread = threading.Thread(target=_bg, name="opf-eager-load", daemon=True)
        _load_thread.start()
        logger.info("OPF eager-load thread started (model=%s device=%s)", MODEL_ID, DEVICE)
    elif not EAGER_LOAD:
        logger.info("OPF eager-load disabled via OPF_EAGER_LOAD=0; lazy on first /detect")
    yield


app = FastAPI(title="PromptGuard OPF service", version="0.1.0a1", lifespan=lifespan)


class DetectRequest(BaseModel):
    text: str


class DetectionItem(BaseModel):
    label: str
    start: int
    end: int
    score: float
    text: str


class DetectResponse(BaseModel):
    detections: list[DetectionItem]


def _load_pipeline() -> Any:
    """Load the HF pipeline once. Errors are captured so /ready can report them."""
    global _pipe, _pipe_load_error
    if _pipe is not None:
        return _pipe
    with _lock:
        if _pipe is not None:
            return _pipe
        try:
            from transformers import pipeline  # heavy import, deferred
        except Exception as exc:
            _pipe_load_error = f"transformers not available: {exc!r}"
            logger.exception("transformers import failed")
            raise
        try:
            logger.info("loading OPF pipeline: model=%s device=%s", MODEL_ID, DEVICE)
            _pipe = pipeline(
                task="token-classification",
                model=MODEL_ID,
                device=DEVICE,
                aggregation_strategy="simple",
            )
            _pipe_load_error = None
            return _pipe
        except Exception as exc:
            _pipe_load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("OPF pipeline load failed")
            raise


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, Any]:
    if _pipe is not None:
        return {"status": "ready", "model": MODEL_ID, "device": DEVICE}
    if _pipe_load_error is not None:
        raise HTTPException(status_code=503, detail={"status": "load_failed", "error": _pipe_load_error})
    raise HTTPException(status_code=503, detail={"status": "loading", "model": MODEL_ID})


@app.post("/detect", response_model=DetectResponse)
def detect(req: DetectRequest) -> DetectResponse:
    try:
        pipe = _load_pipeline()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"pipeline unavailable: {exc!r}") from exc

    raw = pipe(req.text)
    items: list[DetectionItem] = []
    for r in raw:
        # transformers aggregation_strategy="simple" returns:
        # { "entity_group": "...", "score": 0.97, "start": 0, "end": 12, "word": "..." }
        label = str(r.get("entity_group", r.get("entity", "")))
        items.append(
            DetectionItem(
                label=label.lower(),
                start=int(r["start"]),
                end=int(r["end"]),
                score=float(r["score"]),
                text=str(r.get("word", req.text[int(r["start"]) : int(r["end"])])),
            )
        )
    return DetectResponse(detections=items)
