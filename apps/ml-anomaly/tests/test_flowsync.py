"""Flow worker: arrival-driven cursor, complete windows, restarts, backoff (125.23)."""

import dataclasses
import json
import logging

import pytest
from ml_anomaly import flowsync
from ml_anomaly import train as train_mod
from ml_anomaly.clickhouse import ClickHouseError
from ml_anomaly.evaluate import EvalMetrics
from ml_anomaly.flowsync import FlowWorker
from ml_anomaly.metrics import WorkerMetrics
from ml_anomaly.modelstore import ModelStore
from ml_anomaly.state import StateFile
from ml_anomaly.train import FlowSettings, seal_edge

from tests.fakes import TEST_KEY, Conn, FakeClickHouse, store_with_model
from tests.fixtures import baseline_windows

W = 600
# threshold 0: every scored window becomes a row, so "scored" is observable
S = FlowSettings(threshold=0.0)
T0 = 1_794_830_400  # 2026-11-16 12:00:00 UTC


def _worker(tmp_path, ch, settings=S, store=None):
    # trained at T0, so no retraining is due during these tests
    store = store or store_with_model(tmp_path / "models", version="v20261116120000")
    metrics = WorkerMetrics("flow_anomaly")
    state = StateFile(tmp_path / "state" / "flow-cursor.json")
    return FlowWorker(ch, store, settings, metrics, state), metrics


def _sample(metrics, name, **labels):
    return metrics.registry.get_sample_value(name, {"worker": "flow_anomaly", **labels})


def _background(ch, start, end, src="192.168.1.20"):
    """One short flow per minute, arriving 30 s after it ended."""
    for t in range(start, end, 60):
        ch.conns.append(Conn(start=t, duration_s=5, arrived=t + 35, src_ip=src))


def _keys(ch):
    return sorted((a["src_ip"], a["window_start"]) for a in ch.anomalies)


def _run_until(worker, ch, until, step=60):
    while ch.now < until:
        ch.now += step
        worker.cycle()


def test_long_upload_is_scored_exactly_once(tmp_path):
    """ML-2: a 5 GB upload over one 44-minute connection shows up only when
    it ends, stamped with its start; the old 20-minute event-time look-back
    never saw it."""
    ch = FakeClickHouse(now=T0)
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()  # first start: the cursor begins at the current edge
    _background(ch, T0, T0 + 3 * 3600)
    upload = Conn(
        start=T0 + 60,
        duration_s=44 * 60,
        arrived=T0 + 60 + 44 * 60 + 20,
        src_ip="192.168.1.66",
        orig_bytes=5_000_000_000,
        resp_bytes=80_000,
    )
    ch.conns.append(upload)

    _run_until(worker, ch, T0 + 3 * 3600)

    rows = [a for a in ch.anomalies if a["src_ip"] == "192.168.1.66"]
    assert len(rows) == 1
    ended = upload.start + upload.duration_s
    assert rows[0]["window_start"] == ended - ended % W
    assert rows[0]["bytes_out"] == 5_000_000_000
    # and no window of any device was written twice
    assert len(_keys(ch)) == len(set(_keys(ch)))


def test_only_complete_aligned_windows_are_scored(tmp_path):
    """ML-2: the oldest window of each pass used to be a partial slice that
    could overwrite the complete row written earlier."""
    ch = FakeClickHouse(now=T0)
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    _background(ch, T0 - 3600, T0 + 2 * 3600)
    _run_until(worker, ch, T0 + 2 * 3600)
    for start, end in ch.flow_calls:
        assert start % W == 0
        assert end % W == 0
        assert end <= seal_edge(T0 + 2 * 3600, S)
    starts = [s for s, _ in ch.flow_calls]
    assert starts == sorted(set(starts)), "a window range was read twice"
    # every scored window is complete: 10 one-minute flows each
    counts = {}
    for c in ch.conns:
        ended = c.start + c.duration_s
        counts[ended - ended % W] = counts.get(ended - ended % W, 0) + 1
    for a in ch.anomalies:
        assert counts[a["window_start"]] == 10


def test_restart_neither_rescores_nor_skips(tmp_path):
    ch = FakeClickHouse(now=T0)
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    first_edge = worker.cursor
    _background(ch, T0, T0 + 4 * 3600)
    _run_until(worker, ch, T0 + 2 * 3600)
    before = _keys(ch)

    # a new process with the same state directory and model volume
    worker2, _ = _worker(tmp_path, ch, store=ModelStore(tmp_path / "models", TEST_KEY))
    _run_until(worker2, ch, T0 + 4 * 3600)

    keys = _keys(ch)
    assert len(keys) == len(set(keys)), "a window was scored twice"
    assert keys[: len(before)] == before
    # traffic starts at T0; every window from there to the cursor has a row
    assert first_edge <= T0
    expected = list(range(T0, worker2.cursor, W))
    assert sorted({ws for _, ws in keys}) == expected, "a window was skipped"


def test_crash_between_insert_and_cursor_write_writes_nothing_twice(tmp_path, monkeypatch):
    ch = FakeClickHouse(now=T0)
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    _background(ch, T0, T0 + 3 * 3600)
    _run_until(worker, ch, T0 + 3600)

    real_save = StateFile.save

    def crash(_self, _obj):
        raise KeyboardInterrupt("killed after the insert")

    monkeypatch.setattr(StateFile, "save", crash)
    ch.now += 10 * 60
    with pytest.raises(KeyboardInterrupt):
        worker.cycle()
    monkeypatch.setattr(StateFile, "save", real_save)
    written_before_restart = len(ch.anomalies)

    worker2, _ = _worker(tmp_path, ch, store=ModelStore(tmp_path / "models", TEST_KEY))
    _run_until(worker2, ch, T0 + 3 * 3600)
    keys = _keys(ch)
    assert len(keys) == len(set(keys))
    assert len(ch.anomalies) > written_before_restart


def test_backlog_after_outage_lands_in_its_arrival_window(tmp_path):
    """Rows flushed long after they ended are placed by arrival (minus the
    lateness), never into windows that were already scored."""
    ch = FakeClickHouse(now=T0)
    worker, metrics = _worker(tmp_path, ch)
    worker.cycle()
    _run_until(worker, ch, T0 + 3600)
    scored_until = worker.cursor
    # one hour of flows that ended long before the cursor, delivered at once
    for t in range(T0 - 3600, T0, 60):
        ch.conns.append(Conn(start=t, duration_s=1, arrived=T0 + 3600 + 5, src_ip="192.168.1.30"))
    _run_until(worker, ch, T0 + 3 * 3600)
    rows = [a for a in ch.anomalies if a["src_ip"] == "192.168.1.30"]
    assert len(rows) == 1
    assert rows[0]["window_start"] >= scored_until
    assert _sample(metrics, "ml_anomaly_flow_late_rows_total") == 60


def test_no_model_holds_the_cursor_and_backs_off(tmp_path, monkeypatch, caplog):
    """ML-6: with no model the old loop retrained (and stored an artifact)
    every cycle; now it backs off and scores from the held cursor later."""
    bad = EvalMetrics(0.5, 0.1, 40, 30, 0.65)
    monkeypatch.setattr(train_mod, "evaluate", lambda *_a, **_k: bad)
    ch = FakeClickHouse(now=T0, training_windows=_training_windows())
    worker, metrics = _worker(tmp_path, ch, store=ModelStore(tmp_path / "models", TEST_KEY))
    with caplog.at_level(logging.WARNING):
        for _ in range(180):  # three hours of one-minute cycles
            ch.now += 60
            worker.cycle()
    trainings = sum(
        _sample(metrics, "ml_anomaly_trainings_total", outcome=o) or 0
        for o in flowsync.TRAINING_OUTCOMES
    )
    assert trainings == 2  # t=1 min, then +1 h; the next attempt is +2 h later
    assert len(list((tmp_path / "models").glob("*.joblib"))) == 2
    assert _sample(metrics, "ml_anomaly_model_loaded") == 0
    assert _sample(metrics, "ml_anomaly_last_training_healthy") == 0
    assert worker.cursor == seal_edge(T0 + 60, S)  # held
    assert any("not scoring" in r.message for r in caplog.records)

    # a healthy model arrives: scoring resumes from the held cursor
    good = EvalMetrics(0.0, 1.0, 40, 30, 0.0)
    monkeypatch.setattr(train_mod, "evaluate", lambda *_a, **_k: good)
    _background(ch, T0, ch.now)
    ch.now = int(worker.next_training)
    worker.cycle()
    assert _sample(metrics, "ml_anomaly_model_loaded") == 1
    held = seal_edge(T0 + 60, S)
    assert any(start == held for start, _ in ch.flow_calls), "scoring did not resume at the cursor"
    assert min(ws for _, ws in _keys(ch)) == T0  # the first window with traffic


def _training_windows():
    out = []
    for i, w in enumerate(baseline_windows(n=200)):
        out.append(dataclasses.replace(w, window_start=f"2026-11-1{i // 144} 0{i % 10}:00:00"))
    return out


def test_backlog_beyond_the_limit_is_skipped_and_counted(tmp_path):
    ch = FakeClickHouse(now=T0)
    worker, metrics = _worker(
        tmp_path, ch, settings=dataclasses.replace(S, max_backlog_seconds=3600)
    )
    worker.cycle()
    ch.now += 5 * 3600
    worker.cycle()
    assert _sample(metrics, "ml_anomaly_flow_windows_skipped_total", reason="backlog") == 24
    assert worker.cursor == seal_edge(ch.now, S)


def test_window_change_realigns_the_cursor(tmp_path):
    ch = FakeClickHouse(now=T0 + 300)
    state = StateFile(tmp_path / "state" / "flow-cursor.json")
    state.save(
        {"version": 1, "sealed_until": T0 - 300, "window_seconds": 300, "lateness_seconds": 600}
    )
    worker, _ = _worker(tmp_path, ch)
    worker.cycle()
    assert worker.cursor % W == 0
    assert worker.cursor >= T0 - 300


def test_authentication_failure_is_loud(tmp_path, caplog):
    """ML-1: the workers ran every cycle against an account that rejected them,
    logged nothing above Debug-equivalent noise and exported no metrics."""
    ch = FakeClickHouse(now=T0)
    ch.fail_with = ClickHouseError("auth", "ClickHouse rejected user 'ml' (code 516)", 516)
    worker, metrics = _worker(tmp_path, ch)
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            assert metrics.run_cycle(worker.cycle) is False
    assert _sample(metrics, "ml_anomaly_cycle_failures_total", reason="auth") == 3
    assert _sample(metrics, "ml_anomaly_clickhouse_up") == 0
    assert _sample(metrics, "ml_anomaly_last_success_timestamp_seconds") == 0
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "auth" in r.message]
    assert len(warnings) == 3

    ch.fail_with = None
    assert metrics.run_cycle(worker.cycle) is True
    assert _sample(metrics, "ml_anomaly_clickhouse_up") == 1
    assert _sample(metrics, "ml_anomaly_last_success_timestamp_seconds") > 0


def test_missing_ingested_at_column_fails_every_cycle(tmp_path):
    """Until the migration lands the worker must not look healthy, even in
    cycles where no window is due or no model is loaded."""
    ch = FakeClickHouse(now=T0)
    worker, metrics = _worker(tmp_path, ch, store=ModelStore(tmp_path / "empty", TEST_KEY))

    def no_column():
        raise ClickHouseError("schema", "netsoldier.zeek_conn has no ingested_at column", 47)

    ch.check_flow_source = no_column
    for _ in range(3):
        ch.now += 60
        assert metrics.run_cycle(worker.cycle) is False
    assert _sample(metrics, "ml_anomaly_cycle_failures_total", reason="schema") == 3
    assert _sample(metrics, "ml_anomaly_last_success_timestamp_seconds") == 0


def test_unwritable_state_dir_fails_the_cycle(tmp_path):
    ch = FakeClickHouse(now=T0)
    blocker = tmp_path / "state"
    blocker.write_text("a file where the state directory should be")
    worker, metrics = _worker(tmp_path, ch)
    assert metrics.run_cycle(worker.cycle) is False
    assert _sample(metrics, "ml_anomaly_cycle_failures_total", reason="state") == 1
    assert ch.anomalies == []


def test_main_exits_with_configuration_error(monkeypatch, capsys):
    monkeypatch.delenv("CLICKHOUSE_USER", raising=False)
    monkeypatch.setenv("CLICKHOUSE_USERNAME", "legacy")
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "x")
    with pytest.raises(SystemExit) as exc:
        flowsync.main()
    assert exc.value.code == 2
    msgs = [json.loads(line)["msg"] for line in capsys.readouterr().err.splitlines() if line]
    assert any("CLICKHOUSE_USERNAME is no longer read" in m for m in msgs)
