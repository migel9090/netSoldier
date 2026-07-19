"""Thin ClickHouse HTTP client for the beacon consumer.

Uses the HTTP interface with JSONEachRow so the only dependency is httpx
(already required); mirrors the Go services' ClickHouse access pattern.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

from ml_anomaly.beacon import BeaconDetection, BeaconRow
from ml_anomaly.flows import FlowWindow

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ml_anomaly.iforest import FlowAnomaly


class ClickHouseClient:
    def __init__(
        self,
        base_url: str,
        database: str = "netsoldier",
        rita_database: str = "netsoldier_rita",
        username: str = "default",
        password: str = "",
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._database = database
        self._rita_database = rita_database
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "X-ClickHouse-User": username,
                "X-ClickHouse-Key": password,
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ClickHouseClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _query(self, sql: str) -> httpx.Response:
        resp = self._client.post(
            self._base_url, params={"database": self._database}, content=sql
        )
        resp.raise_for_status()
        return resp

    def fetch_beacons(self, min_score: float) -> list[BeaconRow]:
        """Read beacon candidates from RITA's threat_mixtape."""
        # min_score is coerced to float and the database name is
        # server-side config, not user input — no injection surface.
        select = "SELECT src, dst, beacon_score, count AS connection_count, beacon_type, fqdn"
        table = f"{self._rita_database}.threat_mixtape"
        where = f"WHERE beacon_score >= {float(min_score)}"
        sql = f"{select} FROM {table} {where} FORMAT JSONEachRow"
        rows: list[BeaconRow] = []
        for line in self._query(sql).text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(
                BeaconRow(
                    src=str(obj.get("src", "")),
                    dst=str(obj.get("dst", "")),
                    beacon_score=float(obj.get("beacon_score", 0.0)),
                    connection_count=int(obj.get("connection_count", 0)),
                    beacon_type=str(obj.get("beacon_type", "")),
                    fqdn=str(obj.get("fqdn", "")),
                )
            )
        return rows

    def fetch_flow_windows(
        self, window_minutes: int, lookback_minutes: int
    ) -> list[FlowWindow]:
        """Aggregate ``connections`` into per-source windows (step 113).

        Only complete windows are returned — the current, still-filling
        window would always look artificially quiet.
        """
        # Both parameters are coerced to int; no user input reaches the SQL.
        w = int(window_minutes)
        lb = int(lookback_minutes)
        sql = (
            "SELECT toString(toStartOfInterval(timestamp, INTERVAL"  # noqa: S608 — ints only
            f" {w} minute)) AS window_start, src_ip,"
            " count() AS conn_count, sum(bytes_out) AS bytes_out,"
            " sum(bytes_in) AS bytes_in, uniqExact(dst_ip) AS dst_fanout,"
            " uniqExact(dst_port) AS port_fanout,"
            " avg(duration_ms) AS avg_duration_ms"
            " FROM connections"
            f" WHERE timestamp >= now() - INTERVAL {lb} minute"
            f" AND timestamp < toStartOfInterval(now(), INTERVAL {w} minute)"
            " AND src_ip != ''"
            " GROUP BY window_start, src_ip"
            " ORDER BY window_start, src_ip"
            " FORMAT JSONEachRow"
        )
        rows: list[FlowWindow] = []
        for line in self._query(sql).text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(
                FlowWindow(
                    src_ip=str(obj.get("src_ip", "")),
                    window_start=str(obj.get("window_start", "")),
                    conn_count=int(obj.get("conn_count", 0)),
                    bytes_out=int(obj.get("bytes_out", 0)),
                    bytes_in=int(obj.get("bytes_in", 0)),
                    dst_fanout=int(obj.get("dst_fanout", 0)),
                    port_fanout=int(obj.get("port_fanout", 0)),
                    avg_duration_ms=float(obj.get("avg_duration_ms", 0.0)),
                )
            )
        return rows

    def insert_anomalies(self, anomalies: Iterable[FlowAnomaly]) -> int:
        """Append flow anomalies into netsoldier.ml_anomalies."""
        payload = "\n".join(_anomaly_json(a) for a in anomalies)
        if not payload:
            return 0
        sql = "INSERT INTO ml_anomalies FORMAT JSONEachRow"
        self._client.post(
            self._base_url,
            params={"database": self._database, "query": sql},
            content=payload,
        ).raise_for_status()
        return payload.count("\n") + 1

    def insert_beacons(self, detections: Iterable[BeaconDetection]) -> int:
        """Append beacon detections into netsoldier.ml_beacons."""
        payload = "\n".join(_beacon_json(d) for d in detections)
        if not payload:
            return 0
        sql = "INSERT INTO ml_beacons FORMAT JSONEachRow"
        self._client.post(
            self._base_url,
            params={"database": self._database, "query": sql},
            content=payload,
        ).raise_for_status()
        return payload.count("\n") + 1


def _anomaly_json(a: FlowAnomaly) -> str:
    return json.dumps(
        {
            "window_start": a.window_start,
            "src_ip": a.src_ip,
            "anomaly_score": a.anomaly_score,
            "confidence": a.confidence,
            "severity": a.severity,
            "conn_count": a.conn_count,
            "bytes_out": a.bytes_out,
            "bytes_in": a.bytes_in,
            "dst_fanout": a.dst_fanout,
            "port_fanout": a.port_fanout,
            "avg_duration_ms": a.avg_duration_ms,
            "model_version": a.model_version,
            "tags": list(a.tags),
        }
    )


def _beacon_json(d: BeaconDetection) -> str:
    return json.dumps(
        {
            "src_ip": d.src_ip,
            "dst_ip": d.dst_ip,
            "dst_domain": d.dst_domain,
            "beacon_score": d.beacon_score,
            "connection_count": d.connection_count,
            "confidence": d.confidence,
            "severity": d.severity,
            "beacon_type": d.beacon_type,
            "tags": list(d.tags),
        }
    )
