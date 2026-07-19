"""Training pipeline CLI (step 114): fetch baseline → fit → evaluate → store.

Usage: ``python -m ml_anomaly.train [--strict]``

Chronological split (oldest 80% train / newest 20% holdout) so evaluation
never sees training windows and mimics "trained yesterday, scoring
today". The artifact is stored versioned with its eval metrics; when the
metrics miss the health bars the artifact is stored ``healthy=False``
and ``latest`` is NOT flipped, so a bad train can never displace a good
model. ``--strict`` additionally exits 1 for CI/manual gating.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

from ml_anomaly.clickhouse import ClickHouseClient
from ml_anomaly.evaluate import EvalMetrics, evaluate
from ml_anomaly.flows import FEATURE_NAMES, FlowWindow, internal_only
from ml_anomaly.iforest import (
    DEFAULT_SCORE_THRESHOLD,
    MIN_TRAINING_WINDOWS,
    FlowAnomalyModel,
)
from ml_anomaly.modelstore import ModelMetadata, ModelStore, new_version

log = logging.getLogger("ml_anomaly.train")

HOLDOUT_FRACTION = 0.2


def chronological_split(
    windows: list[FlowWindow], holdout_fraction: float = HOLDOUT_FRACTION
) -> tuple[list[FlowWindow], list[FlowWindow]]:
    ordered = sorted(windows, key=lambda w: w.window_start)
    cut = int(len(ordered) * (1 - holdout_fraction))
    return ordered[:cut], ordered[cut:]


def train_once(
    client: ClickHouseClient,
    store: ModelStore,
    window_minutes: int,
    baseline_days: int,
    threshold: float,
) -> tuple[ModelMetadata | None, EvalMetrics | None]:
    """One full pipeline pass. Returns (metadata, metrics); (None, None)
    when there is not enough history to train at all."""
    windows = internal_only(
        client.fetch_flow_windows(
            window_minutes=window_minutes,
            lookback_minutes=baseline_days * 24 * 60,
        )
    )
    train, holdout = chronological_split(windows)
    if len(train) < MIN_TRAINING_WINDOWS or not holdout:
        log.warning(
            "not enough history train=%d holdout=%d need=%d — skipping",
            len(train),
            len(holdout),
            MIN_TRAINING_WINDOWS,
        )
        return None, None

    version = new_version()
    model = FlowAnomalyModel.fit(train, version=version)
    metrics = evaluate(model, holdout, threshold=threshold)
    meta = ModelMetadata(
        version=version,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        feature_names=FEATURE_NAMES,
        training_windows=len(train),
        threshold=threshold,
        metrics=metrics.as_dict(),
        healthy=metrics.healthy,
    )
    if metrics.healthy:
        store.save(model, meta)
        store.prune()
    else:
        # persist for inspection but never promote to `latest`
        previous = store.latest_version()
        store.save(model, meta)
        pointer = store.root / "latest"
        if previous is not None:
            pointer.write_text(previous)
        else:
            pointer.unlink(missing_ok=True)
        log.warning(
            "model %s unhealthy fp_rate=%.3f detection_rate=%.3f — latest stays %s",
            version,
            metrics.fp_rate,
            metrics.detection_rate,
            previous,
        )
    log.info(
        "trained %s windows=%d fp_rate=%.3f detection_rate=%.3f healthy=%s",
        version,
        len(train),
        metrics.fp_rate,
        metrics.detection_rate,
        metrics.healthy,
    )
    return meta, metrics


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format='{"level":"%(levelname)s","msg":"%(message)s"}'
    )
    parser = argparse.ArgumentParser(description="Train the flow anomaly model")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when the trained model misses the health bars",
    )
    args = parser.parse_args()

    base_url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse.netsoldier.svc:8123")
    database = os.environ.get("CLICKHOUSE_DATABASE", "netsoldier")
    username = os.environ.get("CLICKHOUSE_USERNAME", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    window_minutes = int(os.environ.get("FLOW_WINDOW_MINUTES", "10"))
    baseline_days = int(os.environ.get("FLOW_BASELINE_DAYS", "7"))
    threshold = float(
        os.environ.get("FLOW_SCORE_THRESHOLD", str(DEFAULT_SCORE_THRESHOLD))
    )
    model_dir = os.environ.get("MODEL_DIR", "/models")

    with ClickHouseClient(
        base_url, database=database, username=username, password=password
    ) as client:
        meta, metrics = train_once(
            client,
            ModelStore(model_dir),
            window_minutes=window_minutes,
            baseline_days=baseline_days,
            threshold=threshold,
        )
    if meta is None or metrics is None:
        sys.exit(2)
    print(json.dumps({"version": meta.version, **metrics.as_dict()}))
    if args.strict and not metrics.healthy:
        sys.exit(1)


if __name__ == "__main__":
    main()
