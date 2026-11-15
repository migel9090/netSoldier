"""Both workers against a real ClickHouse 24.3 with the repo's migrations (125.23).

Run with tests/integration/run.sh. The flow tests drive the worker with a
simulated server clock: every row is inserted up front with the arrival time
it would have had, and the cursor's arrival bounds decide what the worker may
see at each simulated moment.
"""

import dataclasses
import json
import os
import time
from pathlib import Path

import pytest
from ml_anomaly.clickhouse import ClickHouseClient, ClickHouseError
from ml_anomaly.flowsync import FlowWorker
from ml_anomaly.metrics import WorkerMetrics
from ml_anomaly.modelstore import ModelStore, new_version
from ml_anomaly.state import StateFile
from ml_anomaly.sync import BeaconSettings, BeaconWorker
from ml_anomaly.train import FlowSettings, seal_edge, train_once

from tests.fakes import TEST_KEY, store_with_model
from tests.integration.helpers import URL, needs_clickhouse, worker_client

pytestmark = needs_clickhouse

W = 600
S = FlowSettings(threshold=0.0)  # every scored window becomes a row
DEVICES = [f"192.168.1.{20 + i}" for i in range(6)]
UPLOADER = "192.168.1.66"


class ClockedClient(ClickHouseClient):
    fake_now = 0

    def server_time(self) -> int:
        super().server_time()  # still a real round trip (auth, reachability)
        return self.fake_now


def _utc(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


def _insert_conns(admin, rows):
    body = "\n".join(json.dumps(r) for r in rows).encode()
    admin.run("INSERT INTO netsoldier.zeek_conn FORMAT JSONEachRow", body)


def _conn(
    start, duration_s, arrived, src, orig_bytes=1_000, resp_bytes=20_000, dst="203.0.113.10"
):
    return {
        "timestamp": start,
        "uid": f"C{start}{src}",
        "src_ip": src,
        "src_port": 50000,
        "dst_ip": dst,
        "dst_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration_ms": duration_s * 1000,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": "SF",
        "local_orig": 1,
        "local_resp": 0,
        "history": "ShADadFf",
        "orig_pkts": 10,
        "resp_pkts": 10,
        "ingested_at": _utc(arrived) + ".000",
    }


@pytest.fixture
def scene(admin):
    """Three hours of one-flow-a-minute traffic from six devices, plus one
    5 GB upload over a single 44-minute connection."""
    now = int(admin.scalar("SELECT toUnixTimestamp(now())"))
    base = (now - 4 * 3600) // W * W
    rows = [_conn(t, 5, t + 35, src) for src in DEVICES for t in range(base, base + 3 * 3600, 60)]
    upload_start = base + 60
    upload_end = upload_start + 44 * 60
    rows.append(
        _conn(
            upload_start,
            44 * 60,
            upload_end + 20,
            UPLOADER,
            orig_bytes=5_000_000_000,
            resp_bytes=80_000,
        )
    )
    _insert_conns(admin, rows)
    return {"base": base, "upload_start": upload_start, "upload_end": upload_end}


def _flow_worker(tmp_path, base):
    client = ClockedClient(
        URL, user=os.environ["ML_IT_FLOW_USER"], password=os.environ["ML_IT_FLOW_PASSWORD"]
    )
    models = tmp_path / "models"
    store = (
        ModelStore(models, TEST_KEY)
        if models.exists()
        else store_with_model(models, version=new_version(base))
    )
    worker = FlowWorker(
        client,
        store,
        S,
        WorkerMetrics("flow_anomaly"),
        StateFile(tmp_path / "state" / "flow-cursor.json"),
    )
    return client, worker


def _run(client, worker, start, until):
    client.fake_now = start
    while client.fake_now <= until:
        worker.cycle()
        client.fake_now += 60


def _duplicates(admin):
    return int(
        admin.scalar(
            "SELECT count() FROM (SELECT src_ip, window_start, count() AS c"
            " FROM netsoldier.ml_anomalies GROUP BY src_ip, window_start HAVING c > 1)"
        )
    )


def _keys(admin):
    out = admin.run(
        "SELECT src_ip, toUnixTimestamp(window_start) AS ws FROM netsoldier.ml_anomalies"
        " ORDER BY ws, src_ip FORMAT JSONEachRow"
    )
    return [(r["src_ip"], int(r["ws"])) for r in map(json.loads, out.splitlines())]


def test_long_upload_that_ends_late_is_scored_exactly_once(tmp_path, admin, scene):
    client, worker = _flow_worker(tmp_path, scene["base"])
    _run(client, worker, scene["base"], scene["base"] + 3 * 3600 + 30 * 60)

    rows = [
        line
        for line in admin.run(
            "SELECT src_ip, toUnixTimestamp(window_start) AS ws, bytes_out,"
            " toUnixTimestamp(timestamp) AS ts FROM netsoldier.ml_anomalies FORMAT JSONEachRow"
        ).splitlines()
        if json.loads(line)["src_ip"] == UPLOADER
    ]
    assert len(rows) == 1, rows
    row = json.loads(rows[0])
    end = scene["upload_end"]
    assert int(row["ws"]) == end - end % W  # the window it ended in
    assert int(row["bytes_out"]) == 5_000_000_000
    assert int(row["ts"]) == int(row["ws"]) + W  # observation time = window end
    assert _duplicates(admin) == 0


def test_restart_in_the_middle_scores_every_window_once(tmp_path, admin, scene, monkeypatch):
    base = scene["base"]
    client, worker = _flow_worker(tmp_path, base)
    first_edge = seal_edge(base, S)
    _run(client, worker, base, base + 80 * 60)

    # killed after an insert, before the cursor reached disk
    real_save = StateFile.save

    def killed(_self, _obj):
        raise KeyboardInterrupt("killed after the insert")

    monkeypatch.setattr(StateFile, "save", killed)
    client.fake_now = base + 95 * 60
    with pytest.raises(KeyboardInterrupt):
        worker.cycle()
    monkeypatch.setattr(StateFile, "save", real_save)

    client2, worker2 = _flow_worker(tmp_path, base)
    end = base + 3 * 3600 + 30 * 60
    _run(client2, worker2, base + 96 * 60, end)

    assert _duplicates(admin) == 0, "a window was scored twice"
    keys = _keys(admin)
    cursor = worker2.cursor
    for src in DEVICES:
        got = sorted(ws for s, ws in keys if s == src)
        traffic_until = min(cursor, base + 3 * 3600)
        assert got == list(range(max(first_edge, base), traffic_until, W)), f"{src}: skipped"

    # training reads exactly the windows scoring read
    result = train_once(client2, worker2.store, S, end)
    assert cursor == seal_edge(end, S)
    assert result.windows == len(keys)


def test_missing_ingested_at_is_a_clear_schema_error(admin):
    migration = Path(__file__).parents[4] / "deploy/clickhouse/migrations/011_zeek.sql"
    ddl = migration.read_text().split(";")[0]  # zeek_conn as shipped: no ingested_at
    admin.run("CREATE DATABASE IF NOT EXISTS it_nomig")
    admin.run(ddl.replace("netsoldier.zeek_conn", "it_nomig.zeek_conn"))
    client = ClickHouseClient(
        URL,
        user=os.environ["ML_IT_ADMIN_USER"],
        password=os.environ["ML_IT_ADMIN_PASSWORD"],
        database="it_nomig",
    )
    for call in (client.check_flow_source, lambda: client.fetch_flow_windows(W, W, 0, W)):
        with pytest.raises(ClickHouseError, match="no ingested_at column") as exc:
            call()
        assert exc.value.reason == "schema"
    # and with the migration applied the same check passes for the worker account
    worker_client("flow").check_flow_source()


@pytest.mark.usefixtures("admin")
def test_bad_credentials_and_missing_grants_are_classified():
    bad = ClickHouseClient(URL, user=os.environ["ML_IT_FLOW_USER"], password="wrong")  # noqa: S106
    with pytest.raises(ClickHouseError) as exc:
        bad.server_time()
    assert exc.value.reason == "auth"
    beacon_user = worker_client("beacon")
    with pytest.raises(ClickHouseError) as exc:
        beacon_user.fetch_flow_windows(W, W, 0, W)
    assert exc.value.reason == "access_denied"


# ── beacons ────────────────────────────────────────────────────────────────


def _rita_import(admin, rows, analyzed_at):
    import_id = f"imp{analyzed_at:013d}"[:16]
    body = []
    for r in rows:
        body.append(
            json.dumps(
                {
                    "analyzed_at": _utc(analyzed_at) + ".000000",
                    "import_id": import_id,
                    "hash": r["hash"],
                    "src": r["src"],
                    "dst": r["dst"],
                    "fqdn": r.get("fqdn", ""),
                    "last_seen": r["last_seen"],
                    "count": r.get("count", 0),
                    "beacon_type": r.get("type", ""),
                    "beacon_score": r.get("score", 0.0),
                    "modifier_name": r.get("modifier", ""),
                    "modifier_score": r.get("modifier_score", 0),
                },
                ensure_ascii=False,
            )
        )
    admin.run(
        "INSERT INTO netsoldier_rita.threat_mixtape FORMAT JSONEachRow", "\n".join(body).encode()
    )


def _beacons(admin):
    out = admin.run(
        "SELECT toUnixTimestamp(timestamp) AS ts, src_ip, dst_ip, dst_domain, beacon_score,"
        " severity FROM netsoldier.ml_beacons ORDER BY dst_domain, ts FORMAT JSONEachRow"
    )
    return [json.loads(line) for line in out.split("\n") if line]


def _beacon_worker(tmp_path):
    return BeaconWorker(
        worker_client("beacon"),
        BeaconSettings(),
        WorkerMetrics("beacon_sync"),
        StateFile(tmp_path / "state" / "beacon-state.json"),
    )


def test_unchanged_beacon_over_many_passes_is_emitted_once(tmp_path, admin):
    now = int(admin.scalar("SELECT toUnixTimestamp(now())"))
    seen = now - 600
    odd = "a\u0085b.example"  # U+0085 is emitted unescaped by ClickHouse
    beacons = [
        {
            "hash": "AAAAAAAAAAAAAAAA",
            "src": "::ffff:192.168.1.50",
            "dst": "::",
            "fqdn": "telemetry.vendor.example",
            "type": "sni",
            "score": 0.91,
            "count": 2880,
            "last_seen": seen,
        },
        {
            "hash": "AAAAAAAAAAAAAAAA",
            "src": "::ffff:192.168.1.50",
            "dst": "::",
            "fqdn": "telemetry.vendor.example",
            "modifier": "prevalence",
            "modifier_score": 0.1,
            "last_seen": seen,
        },
        {
            "hash": "BBBBBBBBBBBBBBBB",
            "src": "::ffff:192.168.1.50",
            "dst": "::ffff:203.0.113.9",
            "type": "ip",
            "score": 0.85,
            "count": 1440,
            "last_seen": seen,
        },
        {
            "hash": "CCCCCCCCCCCCCCCC",
            "src": "::ffff:192.168.1.50",
            "dst": "::",
            "fqdn": odd,
            "type": "sni",
            "score": 0.8,
            "count": 700,
            "last_seen": seen,
        },
        {
            "hash": "DDDDDDDDDDDDDDDD",
            "src": "::ffff:192.168.1.51",
            "dst": "::ffff:198.51.100.7",
            "type": "ip",
            "score": 0.5,
            "count": 10,
            "last_seen": seen,
        },
    ]
    _rita_import(admin, beacons, analyzed_at=now - 300)
    worker = _beacon_worker(tmp_path)
    for _ in range(5):
        worker.cycle()
    # RITA's next import re-reports the same, unchanged beacons
    _rita_import(admin, beacons, analyzed_at=now - 60)
    for _ in range(3):
        worker.cycle()
    # restart with the state file, then with the state file lost
    _beacon_worker(tmp_path).cycle()
    (tmp_path / "state" / "beacon-state.json").unlink()
    _beacon_worker(tmp_path).cycle()

    rows = _beacons(admin)
    assert [(r["dst_domain"], r["dst_ip"]) for r in rows] == [
        ("", "203.0.113.9"),
        (odd, ""),
        ("telemetry.vendor.example", ""),
    ]
    assert all(int(r["ts"]) == seen for r in rows)  # RITA's last_seen

    # a material change (medium -> high) is emitted once more
    changed = [dataclasses.replace(_Row(**beacons[2]), score=0.95, last_seen=now - 30).__dict__]
    _rita_import(admin, changed, analyzed_at=now)
    worker.cycle()
    worker.cycle()
    rows = _beacons(admin)
    assert len(rows) == 4
    assert [(r["severity"], int(r["ts"])) for r in rows if r["dst_ip"]] == [
        ("medium", seen),
        ("high", now - 30),
    ]


@dataclasses.dataclass
class _Row:
    hash: str
    src: str
    dst: str
    type: str
    score: float
    count: int
    last_seen: int
    fqdn: str = ""
