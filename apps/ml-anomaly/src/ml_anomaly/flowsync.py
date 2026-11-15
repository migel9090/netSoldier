"""Flow anomaly worker (steps 113, 125.23): Isolation Forest over Zeek conn windows.

EXPERIMENTAL until roadmap step 129: the ``volumetric`` signal this worker
writes to ``ml_anomalies`` is not calibrated on real traffic (audit ML-3).

Scoring is driven by a cursor on *arrival* time, not event time. A conn.log
row appears only when the connection ends, stamped with its start, so the
old "last 20 minutes by timestamp" query never saw a long upload. Rows are
now placed into windows by when they ended, bounded by when they arrived
(``ClickHouseClient.fetch_flow_windows``), and a window is scored once the
server clock has passed its end plus the allowed lateness: then it is
complete and nothing can be added to it.

The cursor (``sealed_until``: end of the newest scored window, always a
window edge) lives in ``STATE_DIR/flow-cursor.json``. It is written after
the anomalies of a pass are inserted, and a pass re-run after a crash skips
rows ``ml_anomalies`` already has, so a restart neither scores a window
twice nor skips one. On first start the cursor begins at the current edge:
flows that arrived before the worker was first deployed are not scored.
If the worker falls more than ``FLOW_MAX_BACKLOG_HOURS`` behind, the oldest
windows are skipped and counted (``ml_anomaly_flow_windows_skipped_total``).

Model lifecycle: at start the worker loads ``latest`` (signed, healthy,
same window size); it retrains every 24 h. A healthy result is promoted, an
unhealthy one is stored for inspection but never served. Failed or
insufficient trainings back off exponentially (1 h, 2 h, ... up to 24 h)
instead of retraining every cycle. Without a model the cursor holds still
and scoring resumes from it once a model exists.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge

from ml_anomaly.clickhouse import ClickHouseClient, ClickHouseError, utc_epoch
from ml_anomaly.config import ConfigError, clickhouse_settings, setup_logging
from ml_anomaly.flows import internal_only
from ml_anomaly.metrics import WorkerMetrics, run_forever
from ml_anomaly.modelstore import (
    REJECTION_REASONS,
    ModelRejectedError,
    ModelStore,
    ModelStoreError,
    SigningKey,
)
from ml_anomaly.state import StateFile
from ml_anomaly.train import FlowSettings, seal_edge, train_once

if TYPE_CHECKING:
    from ml_anomaly.iforest import FlowAnomalyModel
    from ml_anomaly.modelstore import ModelMetadata

log = logging.getLogger("ml_anomaly.flows")

WORKER = "flow_anomaly"
RETRAIN_INTERVAL_SECONDS = 24 * 3600
RETRAIN_BACKOFF_SECONDS = 3600
MAX_WINDOWS_PER_QUERY = 144
CURSOR_VERSION = 1
TRAINING_OUTCOMES = ("healthy", "unhealthy", "insufficient_data", "failed")


class FlowMetrics:
    def __init__(self, base: WorkerMetrics) -> None:
        r, w = base.registry, base.worker
        self.model_loaded = Gauge(
            "ml_anomaly_model_loaded",
            "1 when a verified, healthy model is serving",
            ["worker"],
            registry=r,
        ).labels(w)
        self.model_created = Gauge(
            "ml_anomaly_model_created_timestamp_seconds",
            "Training time of the serving model (0 = none)",
            ["worker"],
            registry=r,
        ).labels(w)
        self.last_training_healthy = Gauge(
            "ml_anomaly_last_training_healthy",
            "1 when the last training produced a healthy model, 0 otherwise or never",
            ["worker"],
            registry=r,
        ).labels(w)
        self.last_training = Gauge(
            "ml_anomaly_last_training_timestamp_seconds",
            "Unix time of the last training attempt (0 = never)",
            ["worker"],
            registry=r,
        ).labels(w)
        self.next_training = Gauge(
            "ml_anomaly_next_training_timestamp_seconds",
            "When the next training attempt is due",
            ["worker"],
            registry=r,
        ).labels(w)
        self._trainings = Counter(
            "ml_anomaly_trainings_total",
            "Training attempts by outcome",
            ["worker", "outcome"],
            registry=r,
        )
        self._rejected = Counter(
            "ml_anomaly_model_rejected_total",
            "Stored models refused at load or promotion, by reason",
            ["worker", "reason"],
            registry=r,
        )
        self.cursor = Gauge(
            "ml_anomaly_flow_cursor_timestamp_seconds",
            "End of the newest window scored (0 = not started)",
            ["worker"],
            registry=r,
        ).labels(w)
        self.windows_scored = Counter(
            "ml_anomaly_flow_windows_scored_total",
            "Device windows scored",
            ["worker"],
            registry=r,
        ).labels(w)
        self._skipped = Counter(
            "ml_anomaly_flow_windows_skipped_total",
            "Window edges never scored, by reason",
            ["worker", "reason"],
            registry=r,
        )
        self.late_rows = Counter(
            "ml_anomaly_flow_late_rows_total",
            "conn rows that arrived later than the allowed lateness",
            ["worker"],
            registry=r,
        ).labels(w)
        self.worker = w
        for o in TRAINING_OUTCOMES:
            self._trainings.labels(w, o)
        for reason in REJECTION_REASONS:
            self._rejected.labels(w, reason)
        for reason in ("backlog", "reconfigured"):
            self._skipped.labels(w, reason)

    def training(self, outcome: str) -> None:
        self._trainings.labels(self.worker, outcome).inc()

    def rejected(self, reason: str | None) -> None:
        if reason in REJECTION_REASONS:
            self._rejected.labels(self.worker, reason).inc()

    def skipped(self, reason: str, n: int) -> None:
        self._skipped.labels(self.worker, reason).inc(n)


class FlowWorker:
    def __init__(
        self,
        client: ClickHouseClient,
        store: ModelStore,
        settings: FlowSettings,
        metrics: WorkerMetrics,
        state: StateFile | None = None,
    ) -> None:
        self.client = client
        self.store = store
        self.s = settings
        self.metrics = metrics
        self.fm = FlowMetrics(metrics)
        self.state = state or StateFile(Path(settings.state_dir) / "flow-cursor.json")
        self.model: FlowAnomalyModel | None = None
        self.meta: ModelMetadata | None = None
        self.cursor: int | None = None
        self.next_training = 0.0
        self.training_failures = 0
        self._load_model(initial=True)

    # ── model lifecycle ──────────────────────────────────────────────────

    def _load_model(self, initial: bool = False) -> None:
        loaded = self.store.load(window_seconds=self.s.window_seconds)
        self.fm.rejected(self.store.last_rejection)
        if loaded is not None:
            self.model, self.meta = loaded
            log.info("serving model %s (trained %s)", self.meta.version, self.meta.created_at)
            if initial:
                self.next_training = self.meta.created_unix + RETRAIN_INTERVAL_SECONDS
        elif initial:
            self.model, self.meta = None, None
        self.fm.model_loaded.set(0 if self.model is None else 1)
        self.fm.model_created.set(0 if self.meta is None else self.meta.created_unix)
        self.fm.next_training.set(self.next_training)

    def _train(self, now: int) -> None:
        self.fm.last_training.set(now)
        try:
            result = train_once(self.client, self.store, self.s, now)
        except (ClickHouseError, ModelStoreError, ModelRejectedError, OSError, ValueError):
            self.fm.training("failed")
            self.fm.last_training_healthy.set(0)
            self._backoff(now)
            raise
        self.fm.training(result.outcome)
        self.fm.last_training_healthy.set(1 if result.outcome == "healthy" else 0)
        if result.outcome == "healthy":
            before = self.meta.version if self.meta else None
            self._load_model()
            if self.meta is not None and self.meta.version != before:
                self.training_failures = 0
                self.next_training = now + RETRAIN_INTERVAL_SECONDS
                self.fm.next_training.set(self.next_training)
                return
        self._backoff(now)
        if self.model is None:
            log.warning(
                "no healthy model: training outcome=%s, scoring paused until a training"
                " succeeds (next attempt in %ds)",
                result.outcome,
                int(self.next_training - now),
            )

    def _backoff(self, now: int) -> None:
        self.training_failures += 1
        delay = min(
            RETRAIN_INTERVAL_SECONDS, RETRAIN_BACKOFF_SECONDS * 2 ** (self.training_failures - 1)
        )
        self.next_training = now + delay
        self.fm.next_training.set(self.next_training)

    # ── cursor ───────────────────────────────────────────────────────────

    def _ensure_cursor(self, now: int) -> None:
        if self.cursor is not None:
            return
        w = self.s.window_seconds
        raw = self.state.load()
        cursor = None
        if isinstance(raw, dict) and raw.get("version") == CURSOR_VERSION:
            try:
                cursor = int(raw["sealed_until"])
                old_w = int(raw["window_seconds"])
                old_l = int(raw["lateness_seconds"])
            except (KeyError, TypeError, ValueError):
                cursor = None
            else:
                if old_w != w or old_l != self.s.lateness_seconds:
                    aligned = -(-cursor // w) * w  # next edge of the new grid
                    log.warning(
                        "window/lateness changed (%ds/%ds -> %ds/%ds); cursor moved from %d to %d",
                        old_w,
                        old_l,
                        w,
                        self.s.lateness_seconds,
                        cursor,
                        aligned,
                    )
                    self.fm.skipped("reconfigured", (aligned - cursor + w - 1) // w)
                    cursor = aligned
        elif raw is not None:
            log.warning("flow cursor state has an unknown format; starting at the current edge")
        if cursor is None:
            cursor = seal_edge(now, self.s)
            log.info("no flow cursor yet; scoring starts with windows ending after %d", cursor)
        self._commit_cursor(cursor)

    def _commit_cursor(self, cursor: int) -> None:
        self.state.save(
            {
                "version": CURSOR_VERSION,
                "sealed_until": cursor,
                "window_seconds": self.s.window_seconds,
                "lateness_seconds": self.s.lateness_seconds,
            }
        )
        self.cursor = cursor
        self.fm.cursor.set(cursor)

    # ── cycle ────────────────────────────────────────────────────────────

    def cycle(self) -> None:
        now = self.client.server_time()
        self.client.check_flow_source()
        self._ensure_cursor(now)
        if now >= self.next_training:
            self._train(now)
        if self.model is None:
            log.warning(
                "no verified healthy model loaded; %s is not scoring (cursor held at %s)",
                WORKER,
                self.cursor,
            )
            return
        self.score(now)

    def score(self, now: int) -> int:
        """Score every window completed since the cursor; returns rows written."""
        if self.model is None or self.cursor is None:
            raise RuntimeError("score() needs a model and a cursor")
        w = self.s.window_seconds
        seal = seal_edge(now, self.s)
        oldest = seal - self.s.max_backlog_seconds // w * w
        if self.cursor < oldest:
            skipped = (oldest - self.cursor) // w
            log.warning(
                "flow cursor %d is more than %dh behind; skipping %d window edges",
                self.cursor,
                self.s.max_backlog_seconds // 3600,
                skipped,
            )
            self.fm.skipped("backlog", skipped)
            self._commit_cursor(oldest)
        written = 0
        while self.cursor < seal:
            start = self.cursor
            end = min(seal, start + MAX_WINDOWS_PER_QUERY * w)
            written += self._score_range(start, end)
            self._commit_cursor(end)
        return written

    def _score_range(self, start: int, end: int) -> int:
        if self.model is None:
            raise RuntimeError("_score_range() needs a model")
        windows = self.client.fetch_flow_windows(
            self.s.window_seconds, self.s.lateness_seconds, start, end
        )
        self.metrics.rows_read.labels(WORKER, "zeek_conn").inc(len(windows))
        late = sum(win.late_rows for win in windows)
        if late:
            self.fm.late_rows.inc(late)
        internal = internal_only(windows)
        anomalies = self.model.detect(internal, threshold=self.s.threshold)
        fresh = anomalies
        if anomalies:
            existing = self.client.existing_anomaly_keys(start, end)
            fresh = [a for a in anomalies if (a.src_ip, utc_epoch(a.window_start)) not in existing]
        written = self.client.insert_anomalies(fresh, self.s.window_seconds)
        self.metrics.rows_written.labels(WORKER, "ml_anomalies").inc(written)
        self.fm.windows_scored.inc(len(internal))
        log.info(
            "flow scoring pass model=%s windows=[%d,%d) device_windows=%d late_rows=%d"
            " anomalies=%d written=%d already_present=%d",
            self.model.version,
            start,
            end,
            len(internal),
            late,
            len(anomalies),
            written,
            len(anomalies) - len(fresh),
        )
        return written


def main() -> None:
    setup_logging()
    try:
        ch = clickhouse_settings()
        s = FlowSettings.from_env()
        key = SigningKey.from_env()
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        sys.exit(2)
    log.info(
        "flow anomaly worker (EXPERIMENTAL volumetric signal) starting clickhouse=%s user=%s"
        " database=%s window=%ds lateness=%ds baseline=%dd interval=%.0fs threshold=%.2f"
        " model_dir=%s state_dir=%s metrics_port=%d",
        ch.url,
        ch.user,
        ch.database,
        s.window_seconds,
        s.lateness_seconds,
        s.baseline_days,
        s.interval_seconds,
        s.threshold,
        s.model_dir,
        s.state_dir,
        s.metrics_port,
    )
    metrics = WorkerMetrics(WORKER)
    metrics.serve(s.metrics_port)
    try:
        store = ModelStore(s.model_dir, key)
        store.prune()
    except OSError as exc:
        log.error("model directory %s unusable: %s", s.model_dir, exc)
        sys.exit(2)
    with ClickHouseClient.from_settings(ch) as client:
        worker = FlowWorker(client, store, s, metrics)
        run_forever(metrics, worker.cycle, s.interval_seconds)


if __name__ == "__main__":
    main()
