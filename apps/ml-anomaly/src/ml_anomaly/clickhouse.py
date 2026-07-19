"""Thin ClickHouse HTTP client for the beacon consumer.

Uses the HTTP interface with JSONEachRow so the only dependency is httpx
(already required); mirrors the Go services' ClickHouse access pattern.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx

from ml_anomaly.beacon import BeaconDetection, BeaconRow

if TYPE_CHECKING:
    from collections.abc import Iterable


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
