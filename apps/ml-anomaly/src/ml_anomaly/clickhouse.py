"""ClickHouse HTTP client for both workers.

Talks to the HTTP interface with ``JSONEachRow`` so the only dependency is
httpx. Credentials go in the ``X-ClickHouse-User`` / ``X-ClickHouse-Key``
headers (contract v2 section 6). Every value that reaches SQL is a typed
query parameter (``{name:Type}``), never string interpolation.

Failures are raised as :class:`ClickHouseError` with a ``reason`` the workers
use as a metric label, so "the password is wrong" and "the server is down"
are visible as different things instead of one generic exception per cycle.

Two parsing rules matter for correctness:

- Rows are split on ``\\n`` only. ``str.splitlines()`` also splits on U+0085,
  U+2028 and other separators that ClickHouse emits unescaped inside JSON
  strings, so one attacker-chosen TLS server name used to break a whole pass.
- 64-bit integers may come back quoted (contract section 6); every integer
  field goes through ``int()``, which accepts both.
"""

from __future__ import annotations

import calendar
import json
import time
from typing import TYPE_CHECKING, Any, NoReturn

import httpx

from ml_anomaly.beacon import BeaconRow, EmittedBeacon
from ml_anomaly.flows import FlowWindow, utc_text

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ml_anomaly.beacon import BeaconDetection
    from ml_anomaly.config import ClickHouseSettings
    from ml_anomaly.iforest import FlowAnomaly

# ClickHouse error codes (src/Common/ErrorCodes.cpp) grouped by what the
# operator has to do about them.
_AUTH_CODES = frozenset({192, 193, 194, 195, 516})  # unknown user, wrong password, ...
_ACCESS_CODES = frozenset({497})  # ACCESS_DENIED: the account lacks a grant
_SCHEMA_CODES = frozenset({16, 47, 60, 81})  # no such column / identifier / table / database

# Sent with every request. validate_utf8 replaces invalid byte sequences in
# String columns (server names, domains) so the body is always valid JSON.
_SETTINGS = {
    "output_format_json_validate_utf8": "1",
    "output_format_json_quote_64bit_integers": "0",
    "output_format_json_quote_denormals": "0",
}

REASONS = ("auth", "access_denied", "schema", "unreachable", "clickhouse", "bad_response")


class ClickHouseError(Exception):
    """A query failed; ``reason`` is one of :data:`REASONS`."""

    def __init__(self, reason: str, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.code = code


class ClickHouseClient:
    def __init__(
        self,
        base_url: str,
        user: str,
        password: str,
        database: str = "netsoldier",
        rita_database: str = "netsoldier_rita",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/") + "/"
        self._user = user
        self.database = database
        self.rita_database = rita_database
        self._client = httpx.Client(
            timeout=timeout,
            transport=transport,
            headers={"X-ClickHouse-User": user, "X-ClickHouse-Key": password},
        )

    @classmethod
    def from_settings(cls, s: ClickHouseSettings, **kw: Any) -> ClickHouseClient:
        return cls(
            s.url,
            user=s.user,
            password=s.password,
            database=s.database,
            rita_database=s.rita_database,
            **kw,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ClickHouseClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── transport ────────────────────────────────────────────────────────

    def _post(
        self,
        sql: str,
        params: dict[str, Any] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
    ) -> bytes:
        query_params: dict[str, str] = dict(_SETTINGS)
        query_params["database"] = self.database
        for name, value in (params or {}).items():
            query_params[f"param_{name}"] = str(value)
        if body is None:
            content = sql.encode()
        else:
            query_params["query"] = sql
            content = body
        kwargs: dict[str, Any] = {}
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            resp = self._client.post(
                self._base_url, params=query_params, content=content, **kwargs
            )
        except httpx.TransportError as exc:
            raise ClickHouseError(
                "unreachable", f"ClickHouse at {self._base_url} is unreachable: {exc!r}"
            ) from exc
        if resp.status_code == 200:
            return resp.content
        raise self._error(resp)

    def _error(self, resp: httpx.Response) -> ClickHouseError:
        header = resp.headers.get("X-ClickHouse-Exception-Code", "")
        code = int(header) if header.isdigit() else None
        text = resp.text.strip().splitlines()[0][:300] if resp.text.strip() else ""
        if code in _AUTH_CODES or (code is None and resp.status_code in (401, 403)):
            return ClickHouseError(
                "auth",
                f"ClickHouse rejected user {self._user!r} (code {code}, HTTP "
                f"{resp.status_code}); check CLICKHOUSE_USER and CLICKHOUSE_PASSWORD: {text}",
                code,
            )
        if code in _ACCESS_CODES:
            return ClickHouseError(
                "access_denied",
                f"ClickHouse user {self._user!r} lacks a grant (code {code}): {text}",
                code,
            )
        if code in _SCHEMA_CODES:
            return ClickHouseError(
                "schema", f"ClickHouse schema mismatch (code {code}): {text}", code
            )
        return ClickHouseError(
            "clickhouse",
            f"ClickHouse query failed (code {code}, HTTP {resp.status_code}): {text}",
            code,
        )

    def _select(
        self, sql: str, params: dict[str, Any] | None = None, timeout: float | None = None
    ) -> list[dict[str, Any]]:
        body = self._post(sql + " FORMAT JSONEachRow", params, timeout=timeout)
        rows: list[dict[str, Any]] = []
        for raw in body.split(b"\n"):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except ValueError as exc:
                raise ClickHouseError(
                    "bad_response", f"unparseable JSONEachRow row: {exc}"
                ) from exc
            if not isinstance(obj, dict):
                raise ClickHouseError("bad_response", "JSONEachRow row is not an object")
            rows.append(obj)
        return rows

    def _insert(self, table: str, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        body = b"\n".join(json.dumps(r, ensure_ascii=False).encode() for r in rows) + b"\n"
        self._post(
            "INSERT INTO {db:Identifier}.{table:Identifier} FORMAT JSONEachRow",
            {"db": self.database, "table": table},
            body=body,
        )
        return len(rows)

    # ── shared ───────────────────────────────────────────────────────────

    def server_time(self) -> int:
        """Unix time on the ClickHouse server.

        ``zeek_conn.ingested_at`` is stamped by the server, so window sealing
        is driven by the server's clock, not the worker's.
        """
        rows = self._select("SELECT toUInt32(toUnixTimestamp(now())) AS t")
        try:
            return int(rows[0]["t"])
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise ClickHouseError("bad_response", f"bad server time response: {rows!r}") from exc

    # ── beacons ──────────────────────────────────────────────────────────

    def fetch_beacons(self, min_score: float, since: int) -> tuple[list[BeaconRow], int]:
        """Latest RITA observation per (src, dst, fqdn) seen since ``since``.

        ``threat_mixtape`` is append-only: every RITA import adds a new row
        per pair, plus separate modifier rows whose beacon_score is 0. The
        newest observation of a pair is the one with the highest
        (last_seen, analyzed_at); only pairs whose *newest* score clears the
        threshold are returned. Returns (rows, rejected_row_count).
        """
        # Aliases never reuse a column name: ClickHouse substitutes aliases
        # into WHERE and into other aggregates.
        sql = (
            "SELECT toString(src) AS src_s, toString(dst) AS dst_s, fqdn AS name,"
            " argMax(beacon_type, (last_seen, analyzed_at)) AS btype,"
            " argMax(beacon_score, (last_seen, analyzed_at)) AS score,"
            " argMax(`count`, (last_seen, analyzed_at)) AS conns,"
            " toUInt32(toUnixTimestamp(max(last_seen))) AS seen"
            " FROM {rita:Identifier}.threat_mixtape"
            " WHERE beacon_score > 0 AND last_seen >= toDateTime({since:UInt32})"
            " GROUP BY src, dst, fqdn"
            " HAVING score >= {min_score:Float64}"
            " ORDER BY src_s, dst_s, name"
        )
        params = {"rita": self.rita_database, "since": int(since), "min_score": float(min_score)}
        out: list[BeaconRow] = []
        rejected = 0
        for obj in self._select(sql, params):
            try:
                out.append(
                    BeaconRow(
                        src=str(obj["src_s"]),
                        dst=str(obj["dst_s"]),
                        beacon_score=float(obj["score"]),
                        connection_count=int(obj["conns"]),
                        beacon_type=str(obj.get("btype") or ""),
                        fqdn=str(obj.get("name") or ""),
                        last_seen=int(obj["seen"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                rejected += 1
        return out, rejected

    def fetch_emitted_beacons(self, since: int) -> list[EmittedBeacon]:
        """The newest row this worker wrote per beacon key since ``since``.

        Used to rebuild emission state when the state file is missing and to
        reconcile it after a crash between an insert and the state write.
        """
        sql = (
            "SELECT src_ip, dst_ip, dst_domain,"
            " argMax(beacon_score, timestamp) AS score,"
            " argMax(severity, timestamp) AS sev,"
            " toUInt32(toUnixTimestamp(max(timestamp))) AS seen"
            " FROM {db:Identifier}.ml_beacons"
            " WHERE timestamp >= toDateTime({since:UInt32})"
            " GROUP BY src_ip, dst_ip, dst_domain"
        )
        out: list[EmittedBeacon] = []
        for obj in self._select(sql, {"db": self.database, "since": int(since)}):
            try:
                out.append(
                    EmittedBeacon(
                        src_ip=str(obj["src_ip"]),
                        dst_ip=str(obj["dst_ip"]),
                        dst_domain=str(obj["dst_domain"]),
                        beacon_score=float(obj["score"]),
                        severity=str(obj["sev"]),
                        last_seen=int(obj["seen"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return out

    def insert_beacons(self, detections: Iterable[BeaconDetection]) -> int:
        """Append beacon detections into ``ml_beacons``.

        ``timestamp`` is RITA's ``last_seen`` for the pair, the time the
        behaviour was observed, not the time this worker happened to copy it.
        """
        return self._insert("ml_beacons", [_beacon_row(d) for d in detections])

    # ── flows ────────────────────────────────────────────────────────────

    def check_flow_source(self) -> None:
        """Fail now, with the reason, if ``zeek_conn`` cannot drive the cursor.

        Reads no rows; run every cycle so a missing migration or a revoked
        grant shows up as a failed cycle even when no window is due.
        """
        try:
            self._select(
                "SELECT ingested_at FROM {db:Identifier}.zeek_conn LIMIT 0", {"db": self.database}
            )
        except ClickHouseError as exc:
            self._raise_explained(exc)

    def _raise_explained(self, exc: ClickHouseError) -> NoReturn:
        if exc.reason == "schema" and "ingested_at" in str(exc):
            raise ClickHouseError(
                "schema",
                f"{self.database}.zeek_conn has no ingested_at column; flow scoring and"
                " training stay off until the migration described in"
                " apps/ml-anomaly/README.md is applied",
                exc.code,
            ) from exc
        raise exc

    def fetch_flow_windows(
        self,
        window_seconds: int,
        lateness_seconds: int,
        start: int,
        end: int,
        timeout: float | None = None,
    ) -> list[FlowWindow]:
        """Per-originator windows over ``zeek_conn`` with start <= window < end.

        A conn.log row is written when the connection ends, stamped with its
        start time, so event time cannot drive a cursor: a 44-minute upload
        shows up 44 minutes "late". Each row is placed by its effective time

            eff = clamp(start_ts + duration, ingested_at - lateness, ingested_at)

        i.e. the time the flow ended, but never later than it arrived and
        never more than ``lateness`` before it arrived. A window
        [w, w + window_seconds) is complete once the server clock has passed
        w + window_seconds + lateness (plus a settle margin, applied by the
        caller): every row placed in it must have arrived by then. Each row
        lands in exactly one window, so a long flow is counted once, in the
        window it ended in, and a backlog flushed after an outage lands in
        the window it arrived in instead of in windows already scored.

        The ``ingested_at`` bounds follow from the clamp and keep the scan
        on the recent parts (with the minmax index the migration adds).
        Requires ``zeek_conn.ingested_at``; a :class:`ClickHouseError` with
        reason ``schema`` is raised until that column exists.
        """
        w, lateness = int(window_seconds), int(lateness_seconds)
        sql = (
            "SELECT toUInt32(bucket) AS window_start, src_ip,"
            " count() AS conn_count, sum(orig_bytes) AS bytes_out,"
            " sum(resp_bytes) AS bytes_in, uniqExact(dst_ip) AS dst_fanout,"
            " uniqExact(dst_port) AS port_fanout, avg(duration_ms) AS avg_duration_ms,"
            " countIf(late) AS late_rows"
            " FROM ("
            "  SELECT src_ip, dst_ip, dst_port, orig_bytes, resp_bytes, duration_ms,"
            "   toInt64(toUnixTimestamp(ingested_at)) AS arr_s,"
            "   toInt64(toUnixTimestamp(timestamp)) + toInt64(intDiv(duration_ms, 1000)) AS end_s,"
            "   greatest(least(end_s, arr_s), arr_s - {lateness:Int64}) AS eff_s,"
            "   intDiv(eff_s, {w:Int64}) * {w:Int64} AS bucket,"
            "   end_s < arr_s - {lateness:Int64} AS late"
            "  FROM {db:Identifier}.zeek_conn"
            "  WHERE ingested_at >= toDateTime({start:UInt32})"
            "   AND ingested_at < toDateTime({arr_end:UInt32})"
            "   AND src_ip != ''"
            " )"
            " WHERE bucket >= {start:Int64} AND bucket < {end:Int64}"
            " GROUP BY bucket, src_ip"
            " ORDER BY bucket, src_ip"
        )
        params = {
            "db": self.database,
            "w": w,
            "lateness": lateness,
            "start": int(start),
            "end": int(end),
            "arr_end": int(end) + lateness,
        }
        try:
            rows = self._select(sql, params, timeout=timeout)
        except ClickHouseError as exc:
            self._raise_explained(exc)
        out: list[FlowWindow] = []
        for obj in rows:
            try:
                out.append(
                    FlowWindow(
                        src_ip=str(obj["src_ip"]),
                        window_start=utc_text(int(obj["window_start"])),
                        conn_count=int(obj["conn_count"]),
                        bytes_out=int(obj["bytes_out"]),
                        bytes_in=int(obj["bytes_in"]),
                        dst_fanout=int(obj["dst_fanout"]),
                        port_fanout=int(obj["port_fanout"]),
                        avg_duration_ms=float(obj["avg_duration_ms"]),
                        late_rows=int(obj["late_rows"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ClickHouseError("bad_response", f"bad flow window row {obj!r}") from exc
        return out

    def existing_anomaly_keys(self, start: int, end: int) -> set[tuple[str, int]]:
        """(src_ip, window_start) already present in ``ml_anomalies``.

        A pass that crashed after its insert but before persisting the cursor
        is re-run on restart; this makes the re-run write nothing twice.
        """
        sql = (
            "SELECT DISTINCT src_ip, toUInt32(toUnixTimestamp(window_start)) AS ws"
            " FROM {db:Identifier}.ml_anomalies"
            " WHERE window_start >= toDateTime({start:UInt32})"
            " AND window_start < toDateTime({end:UInt32})"
        )
        rows = self._select(sql, {"db": self.database, "start": int(start), "end": int(end)})
        return {(str(r["src_ip"]), int(r["ws"])) for r in rows}

    def insert_anomalies(self, anomalies: Iterable[FlowAnomaly], window_seconds: int) -> int:
        """Append flow anomalies into ``ml_anomalies``.

        ``timestamp`` is the end of the window, the time by which the
        behaviour was observed, so a window scored late (after an outage)
        does not look like fresh activity to the correlator.
        """
        return self._insert(
            "ml_anomalies", [_anomaly_row(a, int(window_seconds)) for a in anomalies]
        )


def utc_epoch(text: str) -> int:
    """'YYYY-MM-DD HH:MM:SS' (UTC) -> unix seconds."""
    return calendar.timegm(time.strptime(text, "%Y-%m-%d %H:%M:%S"))


def _anomaly_row(a: FlowAnomaly, window_seconds: int) -> dict[str, Any]:
    start = utc_epoch(a.window_start)
    return {
        "timestamp": start + window_seconds,
        "window_start": start,
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


def _beacon_row(d: BeaconDetection) -> dict[str, Any]:
    return {
        "timestamp": d.last_seen,
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
