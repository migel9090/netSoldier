"""Model store: signed metadata, validated pointer, promotion (steps 114, 125.23).

The attack cases A-D reproduce the audit's ml_digest.py experiment (finding
ML-5): a writer of MODEL_DIR without the signing key must not get code
executed by the worker that unpickles models.
"""

import dataclasses
import hashlib
import json
import logging
import os
import pickle

import pytest
from ml_anomaly import modelstore
from ml_anomaly.config import ConfigError
from ml_anomaly.iforest import FlowAnomalyModel
from ml_anomaly.modelstore import (
    ModelRejectedError,
    ModelStore,
    ModelStoreError,
    SigningKey,
    new_version,
)

from tests.fakes import TEST_KEY, healthy_meta, store_with_model
from tests.fixtures import baseline_windows, exfil_window

V1 = "v20261115120000"
V2 = "v20261116120000"


class Boom:
    """Unpickling this runs a shell command that creates ``marker``."""

    def __init__(self, marker):
        self.marker = str(marker)

    def __reduce__(self):
        return (os.system, (f"echo pwned > {self.marker}",))


def _fit(version):
    return FlowAnomalyModel.fit(baseline_windows(), version=version)


def test_save_promote_load_roundtrip(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    model = _fit(V1)
    store.save(model, healthy_meta(V1))
    store.promote(V1)

    loaded = store.load()
    assert loaded is not None
    reloaded, meta = loaded
    assert meta.version == V1
    assert meta.artifact_sha256
    assert reloaded.scores([exfil_window()]) == model.scores([exfil_window()])


def test_save_never_moves_latest(tmp_path):
    """ML-6: save() used to point `latest` at a model before its health was known."""
    store = store_with_model(tmp_path, V1)
    store.save(_fit(V2), healthy_meta(V2))
    assert store.latest_version() == V1


def test_unhealthy_model_cannot_be_promoted_or_loaded(tmp_path, caplog):
    """ML-6: load() ignored the healthy flag; promotion must require it."""
    store = ModelStore(tmp_path, TEST_KEY)
    store.save(_fit(V1), healthy_meta(V1, healthy=False))
    with pytest.raises(ModelRejectedError, match="health"):
        store.promote(V1)
    assert store.latest_version() is None
    # even if something writes the pointer by hand
    (tmp_path / "latest").write_text(V1)
    with caplog.at_level(logging.WARNING):
        assert store.load() is None
    assert store.last_rejection == "unhealthy"


def test_save_refuses_to_overwrite_a_version(tmp_path):
    store = store_with_model(tmp_path, V1)
    with pytest.raises(ModelStoreError, match="immutable"):
        store.save(_fit(V1), healthy_meta(V1))


def test_save_refuses_malformed_version(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    with pytest.raises(ModelStoreError):
        store.save(_fit("../v1"), dataclasses.replace(healthy_meta(V1), version="../v1"))


def test_version_mismatch_rejected(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    with pytest.raises(ValueError, match="metadata"):
        store.save(_fit(V1), healthy_meta(V2))


def test_load_empty_store_returns_none(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    assert store.load() is None
    assert store.latest_version() is None
    assert store.last_rejection is None


# ── audit attack cases ──────────────────────────────────────────────────────


def test_attack_a_metadata_without_digest_or_signature_is_refused(tmp_path):
    """Audit case A: a new version whose metadata simply has no digest used to
    load with a warning, i.e. the pickle ran."""
    store = store_with_model(tmp_path, V1)
    marker = tmp_path / "MARKER_A"
    (tmp_path / f"iforest-{V2}.joblib").write_bytes(pickle.dumps(Boom(marker)))
    raw = healthy_meta(V2).__dict__ | {"feature_names": list(healthy_meta(V2).feature_names)}
    raw.pop("artifact_sha256")
    (tmp_path / f"iforest-{V2}.json").write_text(json.dumps(raw))
    (tmp_path / "latest").write_text(V2)

    assert store.load() is None
    assert store.last_rejection == "unsigned"
    assert not marker.exists()


def test_attack_b_rewritten_digest_is_refused(tmp_path):
    """Audit case B: replace the current blob and rewrite the digest next to it.
    Without the key the signature over the metadata no longer verifies."""
    store = store_with_model(tmp_path, V1)
    marker = tmp_path / "MARKER_B"
    evil = pickle.dumps(Boom(marker))
    (tmp_path / f"iforest-{V1}.joblib").write_bytes(evil)
    meta_path = tmp_path / f"iforest-{V1}.json"
    meta = json.loads(meta_path.read_text())
    meta["artifact_sha256"] = hashlib.sha256(evil).hexdigest()
    meta_path.write_text(json.dumps(meta))

    assert store.load() is None
    assert store.last_rejection == "bad_signature"
    assert not marker.exists()


def test_attack_b_metadata_signed_with_another_key_is_refused(tmp_path):
    evil_store = ModelStore(tmp_path, SigningKey(b"x" * 32))
    evil_store.save(_fit(V1), healthy_meta(V1))
    evil_store.promote(V1)
    store = ModelStore(tmp_path, TEST_KEY)
    assert store.load() is None
    assert store.last_rejection == "bad_signature"


def test_attack_c_swapped_blob_is_refused(tmp_path):
    """Audit case C: only the blob swapped."""
    store = store_with_model(tmp_path, V1)
    marker = tmp_path / "MARKER_C"
    (tmp_path / f"iforest-{V1}.joblib").write_bytes(pickle.dumps(Boom(marker)))
    assert store.load() is None
    assert store.last_rejection == "digest_mismatch"
    assert not marker.exists()


def test_attack_d_latest_cannot_leave_the_model_dir(tmp_path):
    """Audit case D: `latest` was used as a path component without validation
    and loaded a model from outside MODEL_DIR."""
    models = tmp_path / "models"
    store = store_with_model(models, V1)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = tmp_path / "MARKER_D"
    (outside / "evil.joblib").write_bytes(pickle.dumps(Boom(marker)))
    (outside / "evil.json").write_text("{}")
    (models / "iforest-x").mkdir()
    for pointer in ("x/../../outside/evil", "../outside/evil", "/etc/passwd", "v2026", "V1"):
        (models / "latest").write_text(pointer)
        assert store.load() is None, pointer
        assert store.last_rejection == "bad_pointer"
    assert not marker.exists()


def test_symlinked_pointer_and_artifact_are_refused(tmp_path):
    store = store_with_model(tmp_path / "m", V1)
    root = tmp_path / "m"
    (root / "latest").unlink()
    (tmp_path / "elsewhere").write_text(V1)
    (root / "latest").symlink_to(tmp_path / "elsewhere")
    assert store.load() is None
    assert store.last_rejection == "bad_pointer"

    (root / "latest").unlink()
    (root / "latest").write_text(V1)
    artifact = root / f"iforest-{V1}.joblib"
    artifact.rename(tmp_path / "real.joblib")
    artifact.symlink_to(tmp_path / "real.joblib")
    assert store.load() is None
    assert store.last_rejection == "bad_file"


def test_the_bytes_that_are_hashed_are_the_bytes_unpickled(tmp_path, monkeypatch):
    """The old load() hashed the file, then opened it again to unpickle; a
    swap between the two ran unverified code."""
    store = store_with_model(tmp_path, V1)
    marker = tmp_path / "MARKER_TOCTOU"
    artifact = tmp_path / f"iforest-{V1}.joblib"
    real_read = modelstore._read_regular

    def read_then_swap(path, limit):
        data = real_read(path, limit)
        if path == artifact:
            artifact.write_bytes(pickle.dumps(Boom(marker)))
        return data

    monkeypatch.setattr(modelstore, "_read_regular", read_then_swap)
    loaded = store.load()
    assert loaded is not None
    assert not marker.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [("threshold", None), ("feature_names", 7), ("healthy", "yes"), ("created_at", "x")],
)
def test_damaged_metadata_is_refused_not_raised(tmp_path, field, value):
    """The audit crashed the old server with metadata like threshold=null; a
    damaged (even validly signed) file must be refused cleanly."""
    store = store_with_model(tmp_path, V1)
    meta_path = tmp_path / f"iforest-{V1}.json"
    raw = json.loads(meta_path.read_text())
    raw.pop("signature")
    raw[field] = value
    raw["signature"] = TEST_KEY.sign(modelstore._canonical(raw))
    meta_path.write_text(json.dumps(raw))
    assert store.load() is None
    assert store.last_rejection == "bad_metadata"


def test_truncated_artifact_is_refused(tmp_path):
    store = store_with_model(tmp_path, V1)
    artifact = tmp_path / f"iforest-{V1}.joblib"
    artifact.write_bytes(artifact.read_bytes()[:100])
    assert store.load() is None
    assert store.last_rejection == "digest_mismatch"


def test_incompatible_models_are_refused(tmp_path, monkeypatch):
    store = store_with_model(tmp_path, V1, window_seconds=600)
    assert store.load(window_seconds=300) is None
    assert store.last_rejection == "incompatible"
    monkeypatch.setattr(modelstore.sklearn, "__version__", "0.0.1")
    assert store.load(window_seconds=600) is None
    assert store.last_rejection == "incompatible"


def test_versions_ignores_foreign_names(tmp_path):
    store = store_with_model(tmp_path, V1)
    (tmp_path / "iforest-latest.json").write_text("{}")
    (tmp_path / "iforest-v1.json").write_text("{}")
    assert store.versions() == [V1]


def test_prune_keeps_latest_and_newest(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    versions = [f"v2026111612{i:02d}00" for i in range(7)]
    for v in versions:
        store.save(_fit(v), healthy_meta(v, healthy=False))
    store.save(_fit("v20261101000000"), healthy_meta("v20261101000000"))
    store.promote("v20261101000000")  # the oldest is the serving one
    removed = store.prune(keep=3)
    assert removed == 5
    assert store.versions() == ["v20261101000000", *versions[-2:]]
    assert store.latest_version() == "v20261101000000"


def test_prune_survives_a_planted_directory(tmp_path):
    store = ModelStore(tmp_path, TEST_KEY)
    for i in range(3):
        v = f"v2026111612{i:02d}00"
        store.save(_fit(v), healthy_meta(v, healthy=False))
    (tmp_path / "iforest-v20261101000000.json").mkdir()
    store.prune(keep=1)  # must not raise: a crash here would crash-loop the worker
    assert store.versions() == ["v20261101000000", "v20261116120200"]
    assert (tmp_path / "iforest-v20261101000000.json").is_dir()


def test_new_version_format():
    assert modelstore.VERSION_RE.fullmatch(new_version(1_794_830_400))
    assert new_version(1_794_830_400) == "v20261116120000"


def test_signing_key_from_env(tmp_path):
    key_file = tmp_path / "key"
    key_file.write_text("a" * 64 + "\n")
    assert SigningKey.from_env({"MODEL_SIGNING_KEY_FILE": str(key_file)})
    assert SigningKey.from_env({"MODEL_SIGNING_KEY": "b" * 40})
    with pytest.raises(ConfigError, match="not set"):
        SigningKey.from_env({})
    with pytest.raises(ConfigError, match="at least"):
        SigningKey.from_env({"MODEL_SIGNING_KEY": "short"})
    with pytest.raises(ConfigError, match="not both"):
        SigningKey.from_env({"MODEL_SIGNING_KEY": "b" * 40, "MODEL_SIGNING_KEY_FILE": "x"})
    with pytest.raises(ConfigError, match="unreadable"):
        SigningKey.from_env({"MODEL_SIGNING_KEY_FILE": str(tmp_path / "missing")})
