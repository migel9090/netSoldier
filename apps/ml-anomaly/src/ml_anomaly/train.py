"""Training pipeline (steps 114, 125.23): fetch baseline → fit → evaluate → store.

Usage: ``python -m ml_anomaly.train [--strict]`` (the flow worker runs the
same :func:`train_once` on its own schedule).

The volumetric model is EXPERIMENTAL until roadmap step 129: the health gate
below only checks caricature attacks (audit ML-3).

Training reads exactly the windows the scorer reads: the same
``zeek_conn`` placement rule, and only windows that are already complete
(:func:`seal_edge`), so the two can no longer disagree about what a window
contains. Chronological split (oldest 80% train / newest 20% holdout) so
evaluation never sees training windows.

Every model is stored signed, with its health verdict; only a healthy one is
promoted to ``latest``. Old artifacts are pruned after every training,
healthy or not, so repeated failures cannot fill the volume.

Exit codes of the CLI: 0 trained, 1 unhealthy with ``--strict``, 2 not
enough history, 3 configuration error.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ml_anomaly.clickhouse import ClickHouseClient
from ml_anomaly.config import ConfigError, clickhouse_settings, env_float, env_int, setup_logging
from ml_anomaly.evaluate import EvalMetrics, evaluate
from ml_anomaly.flows import FEATURE_NAMES, FlowWindow, internal_only
from ml_anomaly.iforest import (
    DEFAULT_SCORE_THRESHOLD,
    MIN_TRAINING_WINDOWS,
    FlowAnomalyModel,
)
from ml_anomaly.modelstore import ModelMetadata, ModelStore, SigningKey, new_version
from ml_anomaly.state import DEFAULT_STATE_DIR

if TYPE_CHECKING:
    from collections.abc import Mapping

log = logging.getLogger("ml_anomaly.train")

HOLDOUT_FRACTION = 0.2

# A row stamped by the server at time t is assumed visible to queries by
# t + SETTLE_SECONDS (inserts are synchronous and take well under that).
SETTLE_SECONDS = 60

# Reading a week of zeek_conn takes longer than a scoring query.
TRAINING_QUERY_TIMEOUT = 300.0

KEEP_MODELS = 5


@dataclass(frozen=True)
class FlowSettings:
    window_seconds: int = 600
    lateness_seconds: int = 600
    baseline_days: int = 7
    threshold: float = DEFAULT_SCORE_THRESHOLD
    interval_seconds: float = 60.0
    max_backlog_seconds: int = 24 * 3600
    model_dir: str = "/models"
    state_dir: str = DEFAULT_STATE_DIR
    metrics_port: int = 9102

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> FlowSettings:
        env = os.environ if env is None else env
        window_minutes = env_int(env, "FLOW_WINDOW_MINUTES", 10, 1, 1440)
        if 1440 % window_minutes:
            raise ConfigError(
                f"FLOW_WINDOW_MINUTES must divide a day (1440 minutes), got {window_minutes}"
            )
        return cls(
            window_seconds=window_minutes * 60,
            lateness_seconds=env_int(env, "FLOW_LATENESS_MINUTES", 10, 0, 1440) * 60,
            baseline_days=env_int(env, "FLOW_BASELINE_DAYS", 7, 1, 30),
            threshold=env_float(env, "FLOW_SCORE_THRESHOLD", DEFAULT_SCORE_THRESHOLD, 0.0, 1.0),
            interval_seconds=env_float(env, "FLOW_SYNC_INTERVAL_SECONDS", 60.0, 1.0, 3600.0),
            max_backlog_seconds=env_int(env, "FLOW_MAX_BACKLOG_HOURS", 24, 1, 720) * 3600,
            model_dir=env.get("MODEL_DIR", "/models"),
            state_dir=env.get("STATE_DIR", DEFAULT_STATE_DIR),
            metrics_port=env_int(env, "METRICS_PORT", 9102, 1, 65535),
        )


def seal_edge(now: int, s: FlowSettings) -> int:
    """End of the newest window that is complete at server time ``now``.

    A window [w, w + W) can still receive rows that arrive up to
    ``lateness`` after it ends (see ``fetch_flow_windows``), plus the settle
    margin for visibility.
    """
    t = int(now) - SETTLE_SECONDS - s.lateness_seconds
    return t - t % s.window_seconds


def chronological_split(
    windows: list[FlowWindow], holdout_fraction: float = HOLDOUT_FRACTION
) -> tuple[list[FlowWindow], list[FlowWindow]]:
    ordered = sorted(windows, key=lambda w: (w.window_start, w.src_ip))
    cut = int(len(ordered) * (1 - holdout_fraction))
    return ordered[:cut], ordered[cut:]


@dataclass(frozen=True)
class TrainingResult:
    outcome: str  # healthy | unhealthy | insufficient_data
    meta: ModelMetadata | None
    metrics: EvalMetrics | None
    windows: int


def train_once(
    client: ClickHouseClient,
    store: ModelStore,
    s: FlowSettings,
    now: int,
) -> TrainingResult:
    """One full pipeline pass over the complete windows before ``now``."""
    end = seal_edge(now, s)
    start = end - s.baseline_days * 86400
    windows = internal_only(
        client.fetch_flow_windows(
            s.window_seconds, s.lateness_seconds, start, end, timeout=TRAINING_QUERY_TIMEOUT
        )
    )
    train, holdout = chronological_split(windows)
    if len(train) < MIN_TRAINING_WINDOWS or not holdout:
        log.warning(
            "not enough history to train: train=%d holdout=%d need=%d",
            len(train),
            len(holdout),
            MIN_TRAINING_WINDOWS,
        )
        store.prune(KEEP_MODELS)
        return TrainingResult("insufficient_data", None, None, len(windows))

    stamp = now
    versions = set(store.versions())
    while new_version(stamp) in versions:
        stamp += 1
    version = new_version(stamp)
    model = FlowAnomalyModel.fit(train, version=version)
    metrics = evaluate(model, holdout, threshold=s.threshold)
    meta = ModelMetadata(
        version=version,
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        feature_names=FEATURE_NAMES,
        training_windows=len(train),
        threshold=s.threshold,
        metrics=metrics.as_dict(),
        healthy=metrics.healthy,
        window_seconds=s.window_seconds,
    )
    try:
        meta = store.save(model, meta)
        if metrics.healthy:
            store.promote(version)
    finally:
        store.prune(KEEP_MODELS)
    log.log(
        logging.INFO if metrics.healthy else logging.WARNING,
        "trained %s windows=%d fp_rate=%.3f detection_rate=%.3f healthy=%s latest=%s",
        version,
        len(train),
        metrics.fp_rate,
        metrics.detection_rate,
        metrics.healthy,
        store.latest_version(),
    )
    return TrainingResult(
        "healthy" if metrics.healthy else "unhealthy", meta, metrics, len(windows)
    )


def main() -> None:
    setup_logging()
    parser = argparse.ArgumentParser(description="Train the flow anomaly model once")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 when the trained model misses the health bars",
    )
    args = parser.parse_args()
    try:
        ch = clickhouse_settings()
        s = FlowSettings.from_env()
        key = SigningKey.from_env()
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        sys.exit(3)
    with ClickHouseClient.from_settings(ch) as client:
        result = train_once(client, ModelStore(s.model_dir, key), s, client.server_time())
    if result.meta is None or result.metrics is None:
        sys.exit(2)
    print(json.dumps({"version": result.meta.version, **result.metrics.as_dict()}))
    if args.strict and not result.metrics.healthy:
        sys.exit(1)


if __name__ == "__main__":
    main()
