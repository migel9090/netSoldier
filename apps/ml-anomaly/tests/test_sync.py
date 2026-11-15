"""Beacon sync: emission state, observation time, restart safety (125.23)."""

import json

import pytest
from ml_anomaly import sync
from ml_anomaly.beacon import BeaconRow
from ml_anomaly.clickhouse import ClickHouseError
from ml_anomaly.metrics import WorkerMetrics
from ml_anomaly.state import StateFile
from ml_anomaly.sync import BeaconSettings, BeaconWorker

from tests.fakes import FakeClickHouse

T0 = 1_794_830_400
TELEMETRY = BeaconRow(
    "::ffff:192.168.1.50", "::ffff:203.0.113.9", 0.91, 2880, "ip", "", last_seen=T0 - 600
)


def _worker(tmp_path, ch, **settings):
    metrics = WorkerMetrics("beacon_sync")
    state = StateFile(tmp_path / "state" / "beacon-state.json")
    return BeaconWorker(ch, BeaconSettings(**settings), metrics, state), metrics


def _sample(metrics, name, **labels):
    return metrics.registry.get_sample_value(name, {"worker": "beacon_sync", **labels})


def test_unchanged_beacon_is_emitted_once(tmp_path):
    """ML-4: run_once kept no state and stamped now(): one unchanged beacon
    became a fresh alert every pass (288 a day at the 300 s default)."""
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, metrics = _worker(tmp_path, ch)
    for _ in range(288):
        worker.cycle()
        ch.now += 300
    assert len(ch.beacons) == 1
    assert ch.beacons[0]["timestamp"] == TELEMETRY.last_seen  # RITA's time, not now()
    assert _sample(metrics, "ml_anomaly_beacons_emitted_total", reason="new") == 1


def test_beacon_still_active_is_not_re_emitted(tmp_path):
    """RITA re-reports a live pair on every import with a newer last_seen."""
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, _ = _worker(tmp_path, ch)
    for i in range(48):
        ch.rita = [BeaconRow(**{**TELEMETRY.__dict__, "last_seen": T0 + i * 1800})]
        ch.now = T0 + i * 1800 + 60
        worker.cycle()
    assert len(ch.beacons) == 1


def test_state_survives_a_restart(tmp_path):
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    worker2, _ = _worker(tmp_path, ch)
    for _ in range(5):
        ch.now += 300
        worker2.cycle()
    assert len(ch.beacons) == 1


def test_lost_state_file_is_rebuilt_from_ml_beacons(tmp_path):
    """Also covers a crash between the insert and the state write."""
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    (tmp_path / "state" / "beacon-state.json").unlink()
    worker2, _ = _worker(tmp_path, ch)
    worker2.cycle()
    assert len(ch.beacons) == 1


def test_long_running_beacon_survives_state_loss(tmp_path):
    """Emitted two days ago, still beaconing: not new after the state is lost."""
    ch = FakeClickHouse(now=T0 - 2 * 86400, rita=[_row(0.91, T0 - 2 * 86400 - 60)])
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    (tmp_path / "state" / "beacon-state.json").unlink()
    ch.now = T0
    ch.rita = [_row(0.91, T0 - 60)]
    _worker(tmp_path, ch)[0].cycle()
    assert len(ch.beacons) == 1


def test_corrupt_state_file_is_moved_aside(tmp_path):
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    path = tmp_path / "state" / "beacon-state.json"
    path.parent.mkdir()
    path.write_text("{torn")
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    assert len(ch.beacons) == 1
    assert list(path.parent.glob("beacon-state.json.corrupt-*"))
    assert json.loads(path.read_text())["version"] == 1


def _row(score, seen):
    return BeaconRow(**{**TELEMETRY.__dict__, "beacon_score": score, "last_seen": seen})


def test_material_change_is_re_emitted(tmp_path):
    ch = FakeClickHouse(now=T0, rita=[_row(0.72, T0 - 600)])
    worker, metrics = _worker(tmp_path, ch)
    emitted = []
    for score in (0.72, 0.81, 0.85, 0.95, 0.75, 0.9):
        ch.rita = [_row(score, ch.now - 60)]
        worker.cycle()
        ch.now += 300
        emitted = [(b["beacon_score"], b["severity"]) for b in ch.beacons]
    # 0.81: severity low -> medium; 0.85: +0.04 only; 0.95: high and +0.14;
    # 0.75 and 0.9: below the last emission, never a new alert
    assert emitted == [(0.72, "low"), (0.81, "medium"), (0.95, "high")]
    assert _sample(metrics, "ml_anomaly_beacons_emitted_total", reason="new") == 1
    assert _sample(metrics, "ml_anomaly_beacons_emitted_total", reason="changed") == 2


def test_sni_beacons_are_keyed_by_name(tmp_path):
    """ML-4: RITA stores SNI beacons with dst '::' and the name in fqdn; the
    (src, dst) key collapsed them into one per device."""
    rows = [
        BeaconRow(
            "::ffff:192.168.1.50",
            "::",
            0.98,
            2880,
            "sni",
            "time.vendor.example",
            last_seen=T0 - 60,
        ),
        BeaconRow(
            "::ffff:192.168.1.50", "::", 0.91, 1440, "sni", "c2.evil.example", last_seen=T0 - 60
        ),
        BeaconRow(
            "::ffff:192.168.1.50",
            "::",
            0.88,
            700,
            "sni",
            "UPDATES.other.example.",
            last_seen=T0 - 60,
        ),
    ]
    ch = FakeClickHouse(now=T0, rita=rows)
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    worker.cycle()
    assert sorted(b["dst_domain"] for b in ch.beacons) == [
        "c2.evil.example",
        "time.vendor.example",
        "updates.other.example",
    ]
    assert {b["dst_ip"] for b in ch.beacons} == {""}  # never an IP target of "::"


def test_failed_insert_does_not_advance_the_state(tmp_path):
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, metrics = _worker(tmp_path, ch)
    ch.fail_insert = ClickHouseError("access_denied", "no INSERT grant", 497)
    assert metrics.run_cycle(worker.cycle) is False
    assert _sample(metrics, "ml_anomaly_cycle_failures_total", reason="access_denied") == 1
    ch.fail_insert = None
    assert metrics.run_cycle(worker.cycle) is True
    assert len(ch.beacons) == 1


def test_beacon_that_went_quiet_and_returns_is_new_again(tmp_path):
    ch = FakeClickHouse(now=T0, rita=[TELEMETRY])
    worker, _ = _worker(tmp_path, ch, max_age_seconds=3600)
    worker.cycle()
    ch.rita = []
    ch.now += 2 * 3600
    worker.cycle()
    assert worker.state.entries == {}
    ch.rita = [BeaconRow(**{**TELEMETRY.__dict__, "last_seen": ch.now - 60})]
    worker.cycle()
    assert len(ch.beacons) == 2


def test_old_observations_are_not_emitted(tmp_path):
    stale = BeaconRow(**{**TELEMETRY.__dict__, "last_seen": T0 - 3 * 86400})
    ch = FakeClickHouse(now=T0, rita=[stale])
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    assert ch.beacons == []


def test_main_exits_with_configuration_error(monkeypatch, capsys):
    monkeypatch.delenv("CLICKHOUSE_USER", raising=False)
    monkeypatch.delenv("CLICKHOUSE_PASSWORD", raising=False)
    with pytest.raises(SystemExit) as exc:
        sync.main()
    assert exc.value.code == 2
    msgs = [json.loads(line)["msg"] for line in capsys.readouterr().err.splitlines() if line]
    assert any("CLICKHOUSE_USER is not set" in m for m in msgs)
