"""Prometheus metrics and the cycle loop shared by both workers.

Each worker serves its own registry on ``METRICS_PORT`` (``/metrics``):
beacon-sync defaults to 9101, flow-anomaly to 9102 (both containers share
the pod's network namespace, so they cannot share a port).

Every series a freshness or failure alert needs exists from the first
scrape, with value 0, so an ``absent()`` or ``increase()`` rule does not have
to wait for the first event.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    start_http_server,
)

from ml_anomaly.clickhouse import REASONS, ClickHouseError

if TYPE_CHECKING:
    from collections.abc import Callable

log = logging.getLogger("ml_anomaly.worker")

# ClickHouse reasons plus the worker's own failure classes.
FAILURE_REASONS = (*REASONS, "state", "model_store", "internal")


class WorkerMetrics:
    def __init__(self, worker: str, registry: CollectorRegistry | None = None) -> None:
        self.worker = worker
        self.registry = registry or CollectorRegistry()
        r = self.registry
        lbl = ["worker"]
        self.cycles = Counter(
            "ml_anomaly_cycles_total", "Worker cycles by outcome", [*lbl, "outcome"], registry=r
        )
        self.failures = Counter(
            "ml_anomaly_cycle_failures_total",
            "Failed cycles by reason",
            [*lbl, "reason"],
            registry=r,
        )
        self.last_success = Gauge(
            "ml_anomaly_last_success_timestamp_seconds",
            "Unix time of the last cycle that completed without error (0 = never)",
            lbl,
            registry=r,
        )
        self.duration = Histogram(
            "ml_anomaly_cycle_duration_seconds",
            "Wall time of one cycle",
            lbl,
            buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
            registry=r,
        )
        self.clickhouse_up = Gauge(
            "ml_anomaly_clickhouse_up",
            "1 when ClickHouse was reachable and accepted this worker's credentials"
            " on the last cycle",
            lbl,
            registry=r,
        )
        self.rows_read = Counter(
            "ml_anomaly_rows_read_total", "Rows read from ClickHouse", [*lbl, "table"], registry=r
        )
        self.rows_written = Counter(
            "ml_anomaly_rows_written_total",
            "Rows written to ClickHouse",
            [*lbl, "table"],
            registry=r,
        )
        self.rows_rejected = Counter(
            "ml_anomaly_rows_rejected_total",
            "Rows read but not usable",
            [*lbl, "reason"],
            registry=r,
        )
        for reason in FAILURE_REASONS:
            self.failures.labels(worker, reason)
        for outcome in ("ok", "failed"):
            self.cycles.labels(worker, outcome)
        self.last_success.labels(worker).set(0)
        self.clickhouse_up.labels(worker).set(0)

    def serve(self, port: int, addr: str = "0.0.0.0") -> None:  # noqa: S104 — scraped from the pod network
        ProcessCollector(registry=self.registry)
        PlatformCollector(registry=self.registry)
        start_http_server(port, addr=addr, registry=self.registry)
        log.info("metrics on http://%s:%d/metrics", addr, port)

    def run_cycle(
        self, cycle: Callable[[], object], clock: Callable[[], float] = time.time
    ) -> bool:
        """Run one cycle; classify, log and count any failure. Never raises
        (except for KeyboardInterrupt/SystemExit), so the loop keeps going."""
        started = time.monotonic()
        w = self.worker
        try:
            cycle()
        except ClickHouseError as exc:
            self._failed(exc.reason, f"{exc}")
            # The server answered and accepted the credentials unless the
            # failure says otherwise.
            self.clickhouse_up.labels(w).set(0 if exc.reason in ("unreachable", "auth") else 1)
            return False
        except Exception as exc:
            reason = getattr(exc, "failure_reason", "internal")
            if reason not in FAILURE_REASONS:
                reason = "internal"
            self._failed(reason, f"{type(exc).__name__}: {exc}", exc_info=reason == "internal")
            return False
        finally:
            self.duration.labels(w).observe(time.monotonic() - started)
        self.cycles.labels(w, "ok").inc()
        self.last_success.labels(w).set(clock())
        self.clickhouse_up.labels(w).set(1)
        return True

    def _failed(self, reason: str, message: str, exc_info: bool = False) -> None:
        self.cycles.labels(self.worker, "failed").inc()
        self.failures.labels(self.worker, reason).inc()
        log.warning(
            "%s cycle failed reason=%s: %s", self.worker, reason, message, exc_info=exc_info
        )


def run_forever(
    metrics: WorkerMetrics,
    cycle: Callable[[], object],
    interval: float,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    while True:
        metrics.run_cycle(cycle)
        sleep(interval)
