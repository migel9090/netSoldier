"""Beacon sync worker: periodically turn RITA beacons into detection rows.

Entry point for the ml-anomaly beacon consumer (step 112). Runs a simple
poll loop; the resulting ml_beacons rows are picked up by detection-engine's
unified ingest (step 109) and flow through the normal alert/killswitch path.
"""

from __future__ import annotations

import logging
import os
import time

from ml_anomaly.beacon import DEFAULT_SCORE_THRESHOLD, select_beacons
from ml_anomaly.clickhouse import ClickHouseClient

log = logging.getLogger("ml_anomaly.beacon")


def run_once(client: ClickHouseClient, threshold: float) -> int:
    """One sync pass: read RITA beacons, write detections. Returns count."""
    rows = client.fetch_beacons(min_score=threshold)
    detections = select_beacons(rows, threshold=threshold)
    written = client.insert_beacons(detections)
    log.info(
        "beacon sync pass complete rows=%d detections=%d written=%d",
        len(rows),
        len(detections),
        written,
    )
    return written


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format='{"level":"%(levelname)s","msg":"%(message)s"}'
    )
    base_url = os.environ.get("CLICKHOUSE_URL", "http://clickhouse.netsoldier.svc:8123")
    database = os.environ.get("CLICKHOUSE_DATABASE", "netsoldier")
    rita_database = os.environ.get("RITA_DATABASE", "netsoldier_rita")
    username = os.environ.get("CLICKHOUSE_USERNAME", "default")
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    interval = float(os.environ.get("BEACON_SYNC_INTERVAL_SECONDS", "300"))
    threshold = float(os.environ.get("BEACON_SCORE_THRESHOLD", str(DEFAULT_SCORE_THRESHOLD)))

    log.info("beacon sync starting interval=%.0fs threshold=%.2f", interval, threshold)
    with ClickHouseClient(
        base_url,
        database=database,
        rita_database=rita_database,
        username=username,
        password=password,
    ) as client:
        while True:
            try:
                run_once(client, threshold)
            except Exception:
                log.exception("beacon sync pass failed")  # keep the worker alive
            time.sleep(interval)


if __name__ == "__main__":
    main()
