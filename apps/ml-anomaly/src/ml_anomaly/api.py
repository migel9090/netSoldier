"""Model serving API (step 115): score flow windows over HTTP.

Endpoints:

- ``POST /score``  — score windows with the current model
- ``GET /model``   — metadata of the serving model (version, eval metrics)
- ``GET /healthz`` — liveness (process up, regardless of model state)
- ``GET /readyz``  — readiness (a model is loaded and serving)
- ``GET /metrics`` — Prometheus

The serving model is re-checked against the store's ``latest`` pointer
on every scoring request (a one-line file read), so the API picks up the
daily retrain without restarts and always serves the newest healthy
model.

Run: ``uvicorn --factory ml_anomaly.api:create_app`` (the factory keeps
imports side-effect free — no ModelStore mkdir at import time).
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    generate_latest,
)
from pydantic import BaseModel, Field

from ml_anomaly.flows import FlowWindow
from ml_anomaly.iforest import DEFAULT_SCORE_THRESHOLD
from ml_anomaly.modelstore import ModelStore

log = logging.getLogger("ml_anomaly.api")

SCORE_REQUESTS = Counter(
    "ml_anomaly_score_requests_total",
    "Scoring requests",
    ["outcome"],  # ok | no_model | invalid
)
SCORED_WINDOWS = Counter(
    "ml_anomaly_scored_windows_total", "Windows scored via the API"
)
ANOMALOUS_WINDOWS = Counter(
    "ml_anomaly_api_anomalies_total", "Windows scored at/above threshold"
)
MODEL_LOADED = Gauge(
    "ml_anomaly_model_loaded", "1 when a model artifact is serving"
)


class WindowIn(BaseModel):
    src_ip: str
    window_start: str = ""
    conn_count: int = Field(ge=0)
    bytes_out: int = Field(ge=0)
    bytes_in: int = Field(ge=0)
    dst_fanout: int = Field(ge=0)
    port_fanout: int = Field(ge=0)
    avg_duration_ms: float = Field(ge=0)

    def to_window(self) -> FlowWindow:
        return FlowWindow(**self.model_dump())


class ScoreRequest(BaseModel):
    windows: list[WindowIn] = Field(min_length=1, max_length=10_000)
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class ScoredWindow(BaseModel):
    src_ip: str
    window_start: str
    anomaly_score: float
    confidence: int
    severity: str
    anomalous: bool
    tags: list[str]


class ScoreResponse(BaseModel):
    model_version: str
    threshold: float
    results: list[ScoredWindow]


class _ModelHolder:
    """Keeps the serving model in sync with the store's latest pointer."""

    def __init__(self, store: ModelStore) -> None:
        self.store = store
        self.model = None
        self.meta = None
        self.refresh()

    def refresh(self) -> None:
        latest = self.store.latest_version()
        if latest is None:
            self.model, self.meta = None, None
        elif self.meta is None or self.meta.version != latest:
            loaded = self.store.load(latest)
            if loaded is not None:
                self.model, self.meta = loaded
                log.info("serving model %s", latest)
        MODEL_LOADED.set(0 if self.model is None else 1)


def create_app(store: ModelStore | None = None) -> FastAPI:
    store = store or ModelStore(os.environ.get("MODEL_DIR", "/models"))
    holder = _ModelHolder(store)
    app = FastAPI(title="ml-anomaly", docs_url=None, redoc_url=None)
    app.state.holder = holder

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> dict[str, str]:
        holder.refresh()
        if holder.model is None:
            raise HTTPException(status_code=503, detail="no model loaded")
        return {"status": "ready", "model": holder.meta.version}

    @app.get("/model")
    def model_info() -> dict:
        holder.refresh()
        if holder.meta is None:
            raise HTTPException(status_code=503, detail="no model loaded")
        return asdict(holder.meta)

    @app.post("/score")
    def score(req: ScoreRequest) -> ScoreResponse:
        holder.refresh()
        if holder.model is None:
            SCORE_REQUESTS.labels(outcome="no_model").inc()
            raise HTTPException(status_code=503, detail="no model loaded")
        threshold = (
            req.threshold
            if req.threshold is not None
            else holder.meta.threshold or DEFAULT_SCORE_THRESHOLD
        )
        windows = [w.to_window() for w in req.windows]
        anomalies = {
            (a.src_ip, a.window_start): a
            for a in holder.model.detect(windows, threshold=threshold)
        }
        results = []
        for w, s in zip(windows, holder.model.scores(windows), strict=True):
            hit = anomalies.get((w.src_ip, w.window_start))
            results.append(
                ScoredWindow(
                    src_ip=w.src_ip,
                    window_start=w.window_start,
                    anomaly_score=round(s, 4),
                    confidence=hit.confidence if hit else 0,
                    severity=hit.severity if hit else "none",
                    anomalous=hit is not None,
                    tags=list(hit.tags) if hit else [],
                )
            )
        SCORE_REQUESTS.labels(outcome="ok").inc()
        SCORED_WINDOWS.inc(len(results))
        ANOMALOUS_WINDOWS.inc(sum(1 for r in results if r.anomalous))
        return ScoreResponse(
            model_version=holder.model.version,
            threshold=threshold,
            results=results,
        )

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    _maybe_instrument(app)
    return app


def _maybe_instrument(app: FastAPI) -> None:
    """OTel traces when a collector endpoint is configured (same pattern
    as the Go services: presence of the env var enables the feature)."""
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(
        resource=Resource.create({"service.name": "ml-anomaly"})
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True))
    )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
    log.info("otel tracing enabled endpoint=%s", endpoint)
