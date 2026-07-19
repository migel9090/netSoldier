"""Flow anomaly worker: Isolation Forest over connection windows (step 113).

Fits a baseline model on the household's own recent history, then
periodically scores fresh windows and writes anomalies into
``ml_anomalies``, where detection-engine's unified ingest picks them up
as a volumetric signal for composite-confidence (step 116).

The model refits once a day so the baseline tracks the household (new
devices, seasonal habits) without chasing short-lived spikes.
"""

from __future__ import annotations

import logging
import os
import time

from ml_anomaly.clickhouse import ClickHouseClient
from ml_anomaly.flows import internal_only
from ml_anomaly.iforest import (
    DEFAULT_SCORE_THRESHOLD,
    MIN_TRAINING_WINDOWS,
    FlowAnomalyModel,
)

log = logging.getLogger("ml_anomaly.flows")

REFIT_INTERVAL_SECONDS = 24 * 3600


def fit_baseline(
    client: ClickHouseClient, window_minutes: int, baseline_days: int
) -> FlowAnomalyModel | None:
    """Fit on the trailing baseline; None when there is too little history
    (fresh install, sensor offline) — scoring then waits for data rather
    than alerting on everything."""
    windows = internal_only(
        client.fetch_flow_windows(
            window_minutes=window_minutes,
            lookback_minutes=baseline_days * 24 * 60,
        )
    )
    if len(windows) < MIN_TRAINING_WINDOWS:
        log.warning(
            "baseline too small windows=%d need=%d — skipping fit",
            len(windows),
            MIN_TRAINING_WINDOWS,
        )
        return None
    version = "adhoc-" + time.strftime("%Y%m%d%H%M", time.gmtime())
    model = FlowAnomalyModel.fit(windows, version=version)
    log.info("fitted model version=%s baseline_windows=%d", version, len(windows))
    return model


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
        "flow scoring pass complete windows=%d anomalies=%d written=%d",
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

    log.info(
        "flow anomaly worker starting window=%dm baseline=%dd interval=%.0fs threshold=%.2f",
        window_minutes,
        baseline_days,
        interval,
        threshold,
    )
    model: FlowAnomalyModel | None = None
    fitted_at = 0.0
    with ClickHouseClient(
        base_url, database=database, username=username, password=password
    ) as client:
        while True:
            try:
                if model is None or time.time() - fitted_at > REFIT_INTERVAL_SECONDS:
                    fresh = fit_baseline(client, window_minutes, baseline_days)
                    if fresh is not None:
                        model = fresh
                        fitted_at = time.time()
                if model is not None:
                    score_pass(client, model, window_minutes, threshold)
            except Exception:
                log.exception("flow scoring pass failed")  # keep the worker alive
            time.sleep(interval)


if __name__ == "__main__":
    main()
