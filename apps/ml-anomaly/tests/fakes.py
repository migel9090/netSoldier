"""In-memory stand-ins for ClickHouse used by the hermetic worker tests.

``FakeClickHouse`` implements the client methods the workers call. Its
``fetch_flow_windows`` applies the same placement rule as the SQL in
``ClickHouseClient.fetch_flow_windows`` (written independently here); the
integration tests check the real SQL against a real server.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ml_anomaly.beacon import BeaconRow, EmittedBeacon
from ml_anomaly.clickhouse import ClickHouseError, utc_epoch
from ml_anomaly.flows import FlowWindow, utc_text
from ml_anomaly.iforest import FlowAnomalyModel
from ml_anomaly.modelstore import ModelMetadata, ModelStore, SigningKey

from tests.fixtures import baseline_windows

TEST_KEY = SigningKey(b"k" * 32)


@dataclass
class Conn:
    """One zeek_conn row: start time, duration and arrival (ingested_at)."""

    start: int
    duration_s: int
    arrived: int
    src_ip: str = "192.168.1.50"
    dst_ip: str = "203.0.113.10"
    dst_port: int = 443
    orig_bytes: int = 1_000
    resp_bytes: int = 10_000


@dataclass
class FakeClickHouse:
    now: int = 1_794_830_400  # 2026-11-16 12:00:00 UTC, a window edge
    conns: list[Conn] = field(default_factory=list)
    anomalies: list[dict] = field(default_factory=list)  # rows "written" to ml_anomalies
    rita: list[BeaconRow] = field(default_factory=list)
    beacons: list[dict] = field(default_factory=list)  # rows "written" to ml_beacons
    fail_with: ClickHouseError | None = None
    fail_insert: ClickHouseError | None = None
    flow_calls: list[tuple[int, int]] = field(default_factory=list)
    training_windows: list[FlowWindow] | None = None

    def _check(self) -> None:
        if self.fail_with is not None:
            raise self.fail_with

    def server_time(self) -> int:
        self._check()
        return self.now

    # flows

    def check_flow_source(self):
        self._check()

    def fetch_flow_windows(self, w, lateness, start, end, timeout=None):
        self._check()
        self.flow_calls.append((start, end))
        if self.training_windows is not None and timeout is not None:
            return list(self.training_windows)  # a training read
        groups: dict[tuple[int, str], list[Conn]] = {}
        late: dict[tuple[int, str], int] = {}
        for c in self.conns:
            if c.arrived > self.now:
                continue  # not inserted yet
            end_s = c.start + c.duration_s
            eff = max(min(end_s, c.arrived), c.arrived - lateness)
            bucket = eff - eff % w
            if start <= bucket < end:
                key = (bucket, c.src_ip)
                groups.setdefault(key, []).append(c)
                late[key] = late.get(key, 0) + (1 if end_s < c.arrived - lateness else 0)
        out = []
        for (bucket, src), cs in sorted(groups.items()):
            out.append(
                FlowWindow(
                    src_ip=src,
                    window_start=utc_text(bucket),
                    conn_count=len(cs),
                    bytes_out=sum(c.orig_bytes for c in cs),
                    bytes_in=sum(c.resp_bytes for c in cs),
                    dst_fanout=len({c.dst_ip for c in cs}),
                    port_fanout=len({c.dst_port for c in cs}),
                    avg_duration_ms=sum(c.duration_s * 1000 for c in cs) / len(cs),
                    late_rows=late[(bucket, src)],
                )
            )
        return out

    def existing_anomaly_keys(self, start, end):
        self._check()
        return {
            (a["src_ip"], a["window_start"])
            for a in self.anomalies
            if start <= a["window_start"] < end
        }

    def insert_anomalies(self, anomalies, window_seconds):
        self._check()
        if self.fail_insert is not None:
            raise self.fail_insert
        rows = list(anomalies)
        for a in rows:
            ws = utc_epoch(a.window_start)
            self.anomalies.append(
                {
                    "src_ip": a.src_ip,
                    "window_start": ws,
                    "timestamp": ws + window_seconds,
                    "bytes_out": a.bytes_out,
                    "model_version": a.model_version,
                }
            )
        return len(rows)

    # beacons

    def fetch_beacons(self, min_score, since):
        self._check()
        return [r for r in self.rita if r.beacon_score >= min_score and r.last_seen >= since], 0

    def fetch_emitted_beacons(self, since):
        self._check()
        newest: dict[tuple[str, str, str], dict] = {}
        for b in self.beacons:
            if b["timestamp"] < since:
                continue
            key = (b["src_ip"], b["dst_ip"], b["dst_domain"])
            if key not in newest or b["timestamp"] >= newest[key]["timestamp"]:
                newest[key] = b
        return [
            EmittedBeacon(k[0], k[1], k[2], b["beacon_score"], b["severity"], b["timestamp"])
            for k, b in newest.items()
        ]

    def insert_beacons(self, detections):
        self._check()
        if self.fail_insert is not None:
            raise self.fail_insert
        rows = list(detections)
        for d in rows:
            self.beacons.append(
                {
                    "timestamp": d.last_seen,
                    "src_ip": d.src_ip,
                    "dst_ip": d.dst_ip,
                    "dst_domain": d.dst_domain,
                    "beacon_score": d.beacon_score,
                    "severity": d.severity,
                }
            )
        return len(rows)


def store_with_model(root, version: str = "v20261115120000", window_seconds: int = 600):
    """A ModelStore holding one healthy, promoted model fitted on fixtures."""
    store = ModelStore(root, TEST_KEY)
    model = FlowAnomalyModel.fit(baseline_windows(), version=version)
    store.save(model, healthy_meta(version, window_seconds=window_seconds))
    store.promote(version)
    return store


def healthy_meta(version: str, healthy: bool = True, window_seconds: int = 600) -> ModelMetadata:
    from ml_anomaly.flows import FEATURE_NAMES

    return ModelMetadata(
        version=version,
        created_at=f"{version[1:5]}-{version[5:7]}-{version[7:9]}T{version[9:11]}:"
        f"{version[11:13]}:{version[13:15]}Z",
        feature_names=FEATURE_NAMES,
        training_windows=200,
        threshold=0.65,
        metrics={"fp_rate": 0.01, "detection_rate": 0.97},
        healthy=healthy,
        window_seconds=window_seconds,
    )
