"""Beacon sync worker (steps 112, 125.23): RITA beacons → ``ml_beacons``.

Each cycle reads the newest RITA observation of every (source, destination,
name) seen within ``BEACON_MAX_AGE_HOURS``, and emits a row only for a beacon
that is new or has materially changed since its last emission (see
:class:`ml_anomaly.beacon.EmissionState`). Rows carry RITA's ``last_seen`` as
their timestamp, so an unchanged beacon no longer turns into a "fresh" alert
every five minutes.

Emission state lives in ``STATE_DIR/beacon-state.json``. On start it is also
reconciled with what ``ml_beacons`` already holds, so a lost state file or a
crash between an insert and the state write does not re-emit everything.
detection-engine tails ``ml_beacons`` as the ``beacon`` signal.
"""

from __future__ import annotations

import copy
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from prometheus_client import Counter, Gauge

from ml_anomaly.beacon import (
    DEFAULT_RESCORE_DELTA,
    DEFAULT_SCORE_THRESHOLD,
    EmissionState,
    select_beacons,
)
from ml_anomaly.clickhouse import ClickHouseClient
from ml_anomaly.config import ConfigError, clickhouse_settings, env_float, env_int, setup_logging
from ml_anomaly.metrics import WorkerMetrics, run_forever
from ml_anomaly.state import DEFAULT_STATE_DIR, StateFile

if TYPE_CHECKING:
    from collections.abc import Mapping

log = logging.getLogger("ml_anomaly.beacon")

WORKER = "beacon_sync"
ML_BEACONS_TTL_SECONDS = 30 * 86400


@dataclass(frozen=True)
class BeaconSettings:
    interval_seconds: float = 300.0
    threshold: float = DEFAULT_SCORE_THRESHOLD
    rescore_delta: float = DEFAULT_RESCORE_DELTA
    max_age_seconds: int = 24 * 3600
    state_dir: str = DEFAULT_STATE_DIR
    metrics_port: int = 9101

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> BeaconSettings:
        env = os.environ if env is None else env
        return cls(
            interval_seconds=env_float(env, "BEACON_SYNC_INTERVAL_SECONDS", 300.0, 1.0, 86400.0),
            threshold=env_float(env, "BEACON_SCORE_THRESHOLD", DEFAULT_SCORE_THRESHOLD, 0.0, 1.0),
            rescore_delta=env_float(env, "BEACON_RESCORE_DELTA", DEFAULT_RESCORE_DELTA, 0.0, 1.0),
            max_age_seconds=env_int(env, "BEACON_MAX_AGE_HOURS", 24, 1, 720) * 3600,
            state_dir=env.get("STATE_DIR", DEFAULT_STATE_DIR),
            metrics_port=env_int(env, "METRICS_PORT", 9101, 1, 65535),
        )


class BeaconWorker:
    def __init__(
        self,
        client: ClickHouseClient,
        settings: BeaconSettings,
        metrics: WorkerMetrics,
        state: StateFile | None = None,
    ) -> None:
        self.client = client
        self.s = settings
        self.metrics = metrics
        self.state_file = state or StateFile(Path(settings.state_dir) / "beacon-state.json")
        self.state: EmissionState | None = None
        r = metrics.registry
        self._emitted = Counter(
            "ml_anomaly_beacons_emitted_total",
            "Beacon rows emitted, by why",
            ["worker", "reason"],
            registry=r,
        )
        for reason in ("new", "changed"):
            self._emitted.labels(WORKER, reason)
        self._tracked = Gauge(
            "ml_anomaly_beacons_tracked",
            "Beacons in the emission state",
            ["worker"],
            registry=r,
        ).labels(WORKER)

    def _load_state(self, since: int) -> EmissionState:
        raw = self.state_file.load()
        state = EmissionState()
        if raw is not None:
            try:
                state = EmissionState.from_json(raw)
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("beacon state %s unusable (%s); rebuilding", self.state_file.path, exc)
        adopted = state.absorb_emitted(self.client.fetch_emitted_beacons(since))
        log.info(
            "beacon emission state: %d tracked (%d adopted from ml_beacons)",
            len(state.entries),
            adopted,
        )
        return state

    def cycle(self) -> int:
        now = self.client.server_time()
        cutoff = now - self.s.max_age_seconds
        if self.state is None:
            # every emission ml_beacons still holds (its TTL is 30 days), so a
            # long-running beacon is recognised even after the state file is lost
            self.state = self._load_state(now - ML_BEACONS_TTL_SECONDS)
        rows, rejected = self.client.fetch_beacons(self.s.threshold, cutoff)
        self.metrics.rows_read.labels(WORKER, "threat_mixtape").inc(len(rows) + rejected)
        if rejected:
            self.metrics.rows_rejected.labels(WORKER, "malformed").inc(rejected)
            log.warning("skipped %d malformed threat_mixtape rows", rejected)
        detections = select_beacons(rows, threshold=self.s.threshold)

        # Plan on a copy: the state only advances once the insert succeeded.
        trial = copy.deepcopy(self.state)
        planned = trial.plan(detections, forget_before=cutoff, rescore_delta=self.s.rescore_delta)
        written = self.client.insert_beacons([d for d, _ in planned])
        self.state = trial
        self.metrics.rows_written.labels(WORKER, "ml_beacons").inc(written)
        for _, reason in planned:
            self._emitted.labels(WORKER, reason).inc()
        self._tracked.set(len(trial.entries))
        self.state_file.save(trial.to_json())
        log.info(
            "beacon sync pass rows=%d beacons=%d emitted=%d (new=%d changed=%d) tracked=%d",
            len(rows),
            len(detections),
            written,
            sum(1 for _, r in planned if r == "new"),
            sum(1 for _, r in planned if r == "changed"),
            len(trial.entries),
        )
        return written


def main() -> None:
    setup_logging()
    try:
        ch = clickhouse_settings()
        s = BeaconSettings.from_env()
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        sys.exit(2)
    log.info(
        "beacon sync starting clickhouse=%s user=%s database=%s rita_database=%s"
        " interval=%.0fs threshold=%.2f rescore_delta=%.2f max_age=%dh state_dir=%s"
        " metrics_port=%d",
        ch.url,
        ch.user,
        ch.database,
        ch.rita_database,
        s.interval_seconds,
        s.threshold,
        s.rescore_delta,
        s.max_age_seconds // 3600,
        s.state_dir,
        s.metrics_port,
    )
    metrics = WorkerMetrics(WORKER)
    metrics.serve(s.metrics_port)
    with ClickHouseClient.from_settings(ch) as client:
        worker = BeaconWorker(client, s, metrics)
        run_forever(metrics, worker.cycle, s.interval_seconds)


if __name__ == "__main__":
    main()
