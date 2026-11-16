"""Training pipeline: complete windows only, promotion, pruning (steps 114, 125.23)."""

import dataclasses
import json

import pytest
from ml_anomaly import train as train_mod
from ml_anomaly.evaluate import EvalMetrics
from ml_anomaly.flows import FlowWindow
from ml_anomaly.modelstore import ModelStore
from ml_anomaly.train import FlowSettings, chronological_split, seal_edge, train_once

from tests.fakes import TEST_KEY, FakeClickHouse
from tests.fixtures import baseline_windows

S = FlowSettings()


def _ordered(n=200, seed=7):
    """Baseline windows with distinct, chronological window_start values."""
    out = []
    for i, w in enumerate(baseline_windows(n=n, seed=seed)):
        day, rest = divmod(i, 144)
        out.append(
            dataclasses.replace(
                w, window_start=f"2026-11-{1 + day:02d} {rest // 6:02d}:{rest % 6 * 10:02d}:00"
            )
        )
    return out


def _unhealthy(monkeypatch):
    bad = EvalMetrics(
        fp_rate=0.5, detection_rate=0.1, holdout_windows=40, injected_anomalies=30, threshold=0.65
    )
    monkeypatch.setattr(train_mod, "evaluate", lambda *_a, **_k: bad)


def test_seal_edge_is_a_window_edge_past_lateness_and_settle():
    now = 1_794_830_400 + 1234  # 12:20:34
    edge = seal_edge(now, S)
    assert edge % S.window_seconds == 0
    assert edge + S.lateness_seconds + train_mod.SETTLE_SECONDS <= now
    assert edge + S.window_seconds + S.lateness_seconds + train_mod.SETTLE_SECONDS > now


def test_training_reads_only_complete_aligned_windows(tmp_path):
    """ML-2: the look-back bound was `now - N minutes`, so the oldest window
    was a partial slice; training and scoring must read the same windows."""
    ch = FakeClickHouse(training_windows=_ordered())
    train_once(ch, ModelStore(tmp_path, TEST_KEY), S, ch.now + 1234)
    ((start, end),) = ch.flow_calls
    assert end == seal_edge(ch.now + 1234, S)
    assert start == end - 7 * 86400
    assert start % S.window_seconds == 0


def test_healthy_training_is_promoted(tmp_path):
    ch = FakeClickHouse(training_windows=_ordered())
    store = ModelStore(tmp_path, TEST_KEY)
    result = train_once(ch, store, S, ch.now)
    assert result.outcome == "healthy"
    assert store.latest_version() == result.meta.version
    loaded = store.load(window_seconds=600)
    assert loaded is not None
    assert loaded[1].healthy


def test_unhealthy_first_model_is_stored_but_never_served(tmp_path, monkeypatch):
    """ML-6: with no previous model an unhealthy result used to leave
    `latest` pointing at it until the next line removed it."""
    _unhealthy(monkeypatch)
    ch = FakeClickHouse(training_windows=_ordered())
    store = ModelStore(tmp_path, TEST_KEY)
    result = train_once(ch, store, S, ch.now)
    assert result.outcome == "unhealthy"
    assert store.versions() == [result.meta.version]
    assert store.latest_version() is None
    assert store.load() is None


def test_unhealthy_training_keeps_the_previous_model(tmp_path, monkeypatch):
    ch = FakeClickHouse(training_windows=_ordered())
    store = ModelStore(tmp_path, TEST_KEY)
    good = train_once(ch, store, S, ch.now).meta.version
    _unhealthy(monkeypatch)
    train_once(ch, store, S, ch.now + 3600)
    assert store.latest_version() == good


def test_repeated_unhealthy_training_is_pruned(tmp_path, monkeypatch):
    """ML-6: prune() ran only on the healthy path, so every unhealthy retrain
    left one more artifact until the volume filled."""
    _unhealthy(monkeypatch)
    ch = FakeClickHouse(training_windows=_ordered())
    store = ModelStore(tmp_path, TEST_KEY)
    for i in range(20):
        train_once(ch, store, S, ch.now + i * 3600)
    assert len(store.versions()) == train_mod.KEEP_MODELS
    assert len(list(tmp_path.glob("*.joblib"))) == train_mod.KEEP_MODELS


def test_versions_do_not_collide_within_a_second(tmp_path):
    ch = FakeClickHouse(training_windows=_ordered())
    store = ModelStore(tmp_path, TEST_KEY)
    a = train_once(ch, store, S, ch.now).meta.version
    b = train_once(ch, store, S, ch.now).meta.version
    assert a != b


def test_not_enough_history_stores_nothing(tmp_path):
    ch = FakeClickHouse(training_windows=_ordered(n=30))
    store = ModelStore(tmp_path, TEST_KEY)
    result = train_once(ch, store, S, ch.now)
    assert result.outcome == "insufficient_data"
    assert store.versions() == []


def test_chronological_split_holds_out_newest():
    windows = [
        FlowWindow("192.168.1.5", f"2026-11-16 0{i}:00:00", 1, 1, 1, 1, 1, 1.0)
        for i in reversed(range(10))
    ]
    train, holdout = chronological_split(windows)
    assert [w.window_start[11:13] for w in holdout] == ["08", "09"]
    assert len(train) == 8


def test_settings_validation():
    s = FlowSettings.from_env({"FLOW_WINDOW_MINUTES": "5", "FLOW_LATENESS_MINUTES": "15"})
    assert (s.window_seconds, s.lateness_seconds) == (300, 900)
    with pytest.raises(ValueError, match="divide a day"):
        FlowSettings.from_env({"FLOW_WINDOW_MINUTES": "7"})
    with pytest.raises(ValueError, match="FLOW_SCORE_THRESHOLD"):
        FlowSettings.from_env({"FLOW_SCORE_THRESHOLD": "nan"})


def test_cli_refuses_to_run_without_configuration(monkeypatch, capsys):
    for name in (
        "CLICKHOUSE_USER",
        "CLICKHOUSE_PASSWORD",
        "MODEL_SIGNING_KEY",
        "MODEL_SIGNING_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("sys.argv", ["train"])
    with pytest.raises(SystemExit) as exc:
        train_mod.main()
    assert exc.value.code == 3
    logged = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line]
    assert any("CLICKHOUSE_USER" in e["msg"] for e in logged)
