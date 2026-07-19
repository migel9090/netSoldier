"""Flow anomaly worker: Isolation Forest over connection windows (step 113).

Scores fresh windows with the latest healthy model from the store and
writes anomalies into ``ml_anomalies``, where detection-engine's unified
ingest picks them up as a volumetric signal for composite-confidence
(step 116).

Model lifecycle (step 114): on start the worker loads the newest
persisted artifact; once a day it re-runs the training pipeline
(fit → evaluate → store), which only promotes models that pass the
FP/detection health bars — an unhealthy retrain leaves the previous
model serving.
"""

from __future__ import annotations

import logging
import os
import time

from ml_anomaly.clickhouse import ClickHouseClient
from ml_anomaly.flows import internal_only
from ml_anomaly.iforest import DEFAULT_SCORE_THRESHOLD, FlowAnomalyModel
from ml_anomaly.modelstore import ModelStore
from ml_anomaly.train import train_once

log = logging.getLogger("ml_anomaly.flows")

RETRAIN_INTERVAL_SECONDS = 24 * 3600


def score_pass(
    client: ClickHouseClient,
    model: FlowAnomalyModel,
    window_minutes: int,
    threshold: float,
) -> int:
    """Score the most recent complete windows; returns rows written."""
    windows = internal_only(
        client.fetch_flow_windows(
            window_minutes=window_minutes,
            lookback_minutes=2 * window_minutes,
        )
    )
    anomalies = model.detect(windows, threshold=threshold)
    written = client.insert_anomalies(anomalies)
    log.info(
        "flow scoring pass complete model=%s windows=%d anomalies=%d written=%d",
        model.version,
        len(windows),
        len(anomalies),
        written,
    )
    return written


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format='{"level":"%(levelname)s","msg":"%(message)s"}'
    )
    base_url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse.netsoldier.svc:8123")
    database = os.environ.get("CLICKHOUSE_DATABASE", "netsoldier")
    username = os.environ.get("CLICKHOUSE_USERNAME", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    window_minutes = int(os.environ.get("FLOW_WINDOW_MINUTES", "10"))
    baseline_days = int(os.environ.get("FLOW_BASELINE_DAYS", "7"))
    interval = float(os.environ.get("FLOW_SYNC_INTERVAL_SECONDS", "600"))
    threshold = float(
        os.environ.get("FLOW_SCORE_THRESHOLD", str(DEFAULT_SCORE_THRESHOLD))
    )
    store = ModelStore(os.environ.get("MODEL_DIR", "/models"))

    log.info(
        "flow anomaly worker starting window=%dm baseline=%dd interval=%.0fs threshold=%.2f",
        window_minutes,
        baseline_days,
        interval,
        threshold,
    )
    model: FlowAnomalyModel | None = None
    loaded = store.load()
    if loaded is not None:
        model, meta = loaded
        log.info("loaded model %s (trained %s)", meta.version, meta.created_at)
    trained_at = 0.0
    with ClickHouseClient(
        base_url, database=database, username=username, password=password
    ) as client:
        while True:
            try:
                if model is None or time.time() - trained_at > RETRAIN_INTERVAL_SECONDS:
                    meta, _ = train_once(
                        client,
                        store,
                        window_minutes=window_minutes,
                        baseline_days=baseline_days,
                        threshold=threshold,
                    )
                    if meta is not None:
                        trained_at = time.time()
                    # too little history? retry next cycle, not next day
                    refreshed = store.load()
                    if refreshed is not None:
                        model = refreshed[0]
                if model is not None:
                    score_pass(client, model, window_minutes, threshold)
            except Exception:
                log.exception("flow scoring pass failed")  # keep the worker alive
            time.sleep(interval)


if __name__ == "__main__":
    main()
