"""API tests for the model serving endpoint (step 115)."""

import threading
import time

from fastapi.testclient import TestClient
from ml_anomaly.api import create_app
from ml_anomaly.flows import FEATURE_NAMES
from ml_anomaly.iforest import FlowAnomalyModel
from ml_anomaly.modelstore import ModelMetadata, ModelStore

from tests.fixtures import baseline_windows, exfil_window


def _store_with_model(tmp_path) -> ModelStore:
    store = ModelStore(tmp_path)
    model = FlowAnomalyModel.fit(baseline_windows(), version="v1")
    store.save(
        model,
        ModelMetadata(
            version="v1",
            created_at="2026-07-19T12:00:00Z",
            feature_names=FEATURE_NAMES,
            training_windows=200,
            threshold=0.65,
            metrics={"fp_rate": 0.02, "detection_rate": 0.95},
        ),
    )
    return store


def _payload(window) -> dict:
    return {
        "src_ip": window.src_ip,
        "window_start": window.window_start,
        "conn_count": window.conn_count,
        "bytes_out": window.bytes_out,
        "bytes_in": window.bytes_in,
        "dst_fanout": window.dst_fanout,
        "port_fanout": window.port_fanout,
        "avg_duration_ms": window.avg_duration_ms,
    }


def test_healthz_always_ok(tmp_path):
    client = TestClient(create_app(ModelStore(tmp_path)))
    assert client.get("/healthz").json() == {"status": "ok"}


def test_readyz_and_score_503_without_model(tmp_path):
    client = TestClient(create_app(ModelStore(tmp_path)))
    assert client.get("/readyz").status_code == 503
    resp = client.post(
        "/score", json={"windows": [_payload(exfil_window())]}
    )
    assert resp.status_code == 503


def test_model_info(tmp_path):
    client = TestClient(create_app(_store_with_model(tmp_path)))
    info = client.get("/model").json()
    assert info["version"] == "v1"
    assert info["metrics"]["detection_rate"] == 0.95
    assert client.get("/readyz").json()["model"] == "v1"


def test_score_flags_exfil_not_baseline(tmp_path):
    client = TestClient(create_app(_store_with_model(tmp_path)))
    normal = baseline_windows(n=5, seed=42)
    windows = [_payload(w) for w in [*normal, exfil_window()]]
    resp = client.post("/score", json={"windows": windows})
    assert resp.status_code == 200
    body = resp.json()
    assert body["model_version"] == "v1"
    assert body["threshold"] == 0.65
    results = body["results"]
    assert len(results) == 6
    exfil = results[-1]
    assert exfil["anomalous"] is True
    assert exfil["severity"] in {"low", "medium", "high"}
    assert exfil["confidence"] >= 40
    assert "upload-heavy" in exfil["tags"]
    assert sum(1 for r in results[:-1] if r["anomalous"]) == 0


def test_score_custom_threshold(tmp_path):
    client = TestClient(create_app(_store_with_model(tmp_path)))
    resp = client.post(
        "/score",
        json={"windows": [_payload(exfil_window())], "threshold": 0.99},
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["anomalous"] is False


def test_score_validation_rejects_negative_counts(tmp_path):
    client = TestClient(create_app(_store_with_model(tmp_path)))
    bad = _payload(exfil_window())
    bad["conn_count"] = -1
    resp = client.post("/score", json={"windows": [bad]})
    assert resp.status_code == 422


def test_api_picks_up_newer_model(tmp_path):
    store = _store_with_model(tmp_path)
    client = TestClient(create_app(store))
    assert client.get("/model").json()["version"] == "v1"
    model2 = FlowAnomalyModel.fit(baseline_windows(seed=11), version="v2")
    store.save(
        model2,
        ModelMetadata(
            version="v2",
            created_at="2026-07-20T12:00:00Z",
            feature_names=FEATURE_NAMES,
            training_windows=200,
            threshold=0.65,
        ),
    )
    assert client.get("/model").json()["version"] == "v2"


def test_metrics_exposed(tmp_path):
    client = TestClient(create_app(_store_with_model(tmp_path)))
    client.post("/score", json={"windows": [_payload(exfil_window())]})
    text = client.get("/metrics").text
    assert "ml_anomaly_score_requests_total" in text
    assert "ml_anomaly_model_loaded 1.0" in text


def test_score_runs_the_forest_once(tmp_path, monkeypatch):
    """detect() recomputes the same scores internally.

    Calling scores() and detect() separately ran the forest twice over every
    window — up to 10,000 of them per request.
    """
    store = _store_with_model(tmp_path)
    app = create_app(store)
    serving, _ = app.state.holder.current()

    calls = {"n": 0}
    original = serving.scores

    def counting_scores(windows):
        calls["n"] += 1
        return original(windows)

    monkeypatch.setattr(serving, "scores", counting_scores)

    client = TestClient(app)
    resp = client.post("/score", json={"windows": [_payload(exfil_window())]})
    assert resp.status_code == 200
    assert calls["n"] == 1, f"forest should run once per request, ran {calls['n']}x"


def test_concurrent_scoring_is_race_free(tmp_path):
    """FastAPI runs ``def`` endpoints in a threadpool.

    Before the holder took a lock, one thread could clear the model between
    another thread's None-check and its use, producing a 500 rather than a
    score or a clean 503.
    """
    store = _store_with_model(tmp_path)
    app = create_app(store)
    client = TestClient(app)
    holder = app.state.holder

    errors: list[int] = []
    stop = threading.Event()

    def hammer():
        while not stop.is_set():
            resp = client.post("/score", json={"windows": [_payload(exfil_window())]})
            if resp.status_code not in (200, 503):
                errors.append(resp.status_code)

    def churn():
        while not stop.is_set():
            holder.refresh()

    threads = [threading.Thread(target=hammer) for _ in range(4)]
    threads.append(threading.Thread(target=churn))
    for t in threads:
        t.start()
    time.sleep(1.0)
    stop.set()
    for t in threads:
        t.join()

    assert not errors, f"concurrent scoring produced unexpected statuses: {set(errors)}"


def test_refresh_returns_current_pair(tmp_path):
    store = _store_with_model(tmp_path)
    app = create_app(store)
    model, meta = app.state.holder.refresh()
    assert model is not None
    assert meta is not None
    assert meta.version == "v1"
