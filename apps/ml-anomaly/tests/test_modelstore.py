"""Unit tests for versioned model persistence (step 114)."""

import json
import logging

import pytest
from ml_anomaly.iforest import FlowAnomalyModel
from ml_anomaly.modelstore import ModelMetadata, ModelStore

from tests.fixtures import baseline_windows as _baseline_windows
from tests.fixtures import exfil_window as _exfil_window


def _meta(version: str, healthy: bool = True) -> ModelMetadata:
    return ModelMetadata(
        version=version,
        created_at="2026-07-19T12:00:00Z",
        feature_names=("log_bytes_out",),
        training_windows=200,
        threshold=0.65,
        metrics={"fp_rate": 0.01, "detection_rate": 0.97},
        healthy=healthy,
    )


def test_save_load_roundtrip(tmp_path):
    store = ModelStore(tmp_path)
    model = FlowAnomalyModel.fit(_baseline_windows(), version="v1")
    store.save(model, _meta("v1"))

    loaded = store.load()
    assert loaded is not None
    reloaded, meta = loaded
    assert meta.version == "v1"
    assert meta.metrics["detection_rate"] == 0.97
    # the reloaded forest scores identically
    assert reloaded.scores([_exfil_window()]) == model.scores([_exfil_window()])


def test_version_mismatch_rejected(tmp_path):
    store = ModelStore(tmp_path)
    model = FlowAnomalyModel.fit(_baseline_windows(), version="v1")
    with pytest.raises(ValueError, match="metadata"):
        store.save(model, _meta("v2"))


def test_latest_follows_most_recent_save(tmp_path):
    store = ModelStore(tmp_path)
    for v in ("v1", "v2"):
        store.save(FlowAnomalyModel.fit(_baseline_windows(), version=v), _meta(v))
    assert store.latest_version() == "v2"
    assert store.versions() == ["v1", "v2"]
    # explicit older version still loadable
    older = store.load("v1")
    assert older is not None
    assert older[1].version == "v1"


def test_load_empty_store_returns_none(tmp_path):
    assert ModelStore(tmp_path).load() is None
    assert ModelStore(tmp_path).latest_version() is None


def test_load_corrupt_metadata_returns_none(tmp_path):
    store = ModelStore(tmp_path)
    model = FlowAnomalyModel.fit(_baseline_windows(), version="v1")
    store.save(model, _meta("v1"))
    (tmp_path / "iforest-v1.json").write_text("{not json")
    assert store.load() is None


def test_prune_keeps_newest_and_latest(tmp_path):
    store = ModelStore(tmp_path)
    for v in ("v1", "v2", "v3", "v4", "v5", "v6", "v7"):
        store.save(FlowAnomalyModel.fit(_baseline_windows(), version=v), _meta(v))
    removed = store.prune(keep=3)
    assert removed == 4
    assert store.versions() == ["v5", "v6", "v7"]
    assert store.latest_version() == "v7"


def test_save_records_artifact_digest(tmp_path):
    """The digest is what lets load() refuse a swapped model blob."""
    store = ModelStore(tmp_path)
    store.save(FlowAnomalyModel.fit(_baseline_windows(), version="v1"), _meta("v1"))

    raw = json.loads((tmp_path / "iforest-v1.json").read_text())
    assert raw["artifact_sha256"], "save() must record the artifact digest"
    assert len(raw["artifact_sha256"]) == 64


def test_load_refuses_tampered_artifact(tmp_path, caplog):
    """joblib.load unpickles, i.e. executes arbitrary code.

    The model lives on a shared PVC and the API reloads it whenever `latest`
    changes, so anything able to write to that volume could get code execution
    in a pod that holds ClickHouse credentials. A swapped .joblib has to be
    refused BEFORE it is unpickled.
    """
    store = ModelStore(tmp_path)
    store.save(FlowAnomalyModel.fit(_baseline_windows(), version="v1"), _meta("v1"))

    (tmp_path / "iforest-v1.joblib").write_bytes(b"not the model that was trained")

    with caplog.at_level(logging.ERROR):
        assert store.load("v1") is None, (
            "a model whose digest does not match its metadata must not be loaded"
        )
    assert any("digest" in r.message for r in caplog.records)


def test_load_accepts_legacy_artifact_without_digest(tmp_path, caplog):
    """Artifacts written before step 124 carry no digest.

    Refusing them would take detection offline on upgrade, so they load with a
    warning instead of being rejected.
    """
    store = ModelStore(tmp_path)
    store.save(FlowAnomalyModel.fit(_baseline_windows(), version="v1"), _meta("v1"))

    meta_path = tmp_path / "iforest-v1.json"
    raw = json.loads(meta_path.read_text())
    del raw["artifact_sha256"]
    meta_path.write_text(json.dumps(raw))

    with caplog.at_level(logging.WARNING):
        loaded = store.load("v1")
    assert loaded is not None, "a legacy artifact should still serve"
    assert any("artifact_sha256" in r.message for r in caplog.records)


def test_load_returns_none_for_corrupt_metadata(tmp_path):
    store = ModelStore(tmp_path)
    store.save(FlowAnomalyModel.fit(_baseline_windows(), version="v1"), _meta("v1"))
    (tmp_path / "iforest-v1.json").write_text("{not json")
    assert store.load("v1") is None
