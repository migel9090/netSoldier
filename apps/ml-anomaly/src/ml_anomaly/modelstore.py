"""Versioned, signed persistence for flow anomaly models (steps 114, 125.23).

Layout under ``MODEL_DIR``::

    iforest-v20261116120000.joblib   # the fitted forest (a pickle)
    iforest-v20261116120000.json     # metadata, artifact SHA-256, HMAC signature
    latest                           # version of the current HEALTHY model

Why the signature: ``joblib.load`` unpickles, i.e. runs code, inside the flow
worker, which holds ClickHouse credentials. A digest stored next to the
artifact only proves that whoever wrote the blob also wrote the JSON, and
both sit on the same volume. The trusted value therefore comes from
somewhere else: the metadata, which carries the artifact's SHA-256, is
signed with HMAC-SHA256 under a key that is mounted from a Kubernetes
Secret (``MODEL_SIGNING_KEY_FILE``) and never written to the model volume.
Something that can write the volume but cannot read that Secret cannot
produce an artifact this store will unpickle.

Rules enforced here:

- ``latest`` (and any version asked for) must match ``v`` + 14 digits, so it
  can never name a path outside ``MODEL_DIR``; files are opened with
  ``O_NOFOLLOW`` and must be regular files of bounded size.
- Metadata without a signature or without a digest is refused; there is no
  legacy mode.
- The artifact is read into memory once; the same bytes are hashed and
  unpickled.
- ``save`` never moves ``latest``. :meth:`ModelStore.promote` does, and only
  for a model whose signed metadata says it passed the health gate;
  :meth:`ModelStore.load` refuses unhealthy models.

Not covered: anyone who can read the signing key (or the flow worker's
memory) can sign; a writer of the volume can delete models or point
``latest`` at an older model that was itself signed and healthy (rollback);
a signed model is trusted to be the forest the trainer produced, so data
poisoning (audit ML-7) is a separate problem.
"""

from __future__ import annotations

import calendar
import dataclasses
import hashlib
import hmac
import io
import json
import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib
import sklearn
from sklearn.ensemble import IsolationForest

from ml_anomaly.config import ConfigError
from ml_anomaly.flows import FEATURE_NAMES
from ml_anomaly.iforest import FlowAnomalyModel
from ml_anomaly.state import fsync_dir

if TYPE_CHECKING:
    from collections.abc import Mapping

log = logging.getLogger("ml_anomaly.modelstore")

_PREFIX = "iforest-"
VERSION_RE = re.compile(r"v[0-9]{14}")
MIN_KEY_BYTES = 32
MAX_ARTIFACT_BYTES = 256 << 20
MAX_METADATA_BYTES = 1 << 20
_SIGNATURE_CONTEXT = b"netsoldier/ml-anomaly/model-metadata/v1\n"

REJECTION_REASONS = (
    "bad_pointer",
    "missing",
    "bad_file",
    "bad_metadata",
    "unsigned",
    "bad_signature",
    "unhealthy",
    "digest_mismatch",
    "incompatible",
    "unpickle_failed",
)


class ModelStoreError(Exception):
    """The store cannot do what was asked (disk full, version exists, ...)."""

    failure_reason = "model_store"


class ModelRejectedError(Exception):
    """A stored model failed verification; ``reason`` in REJECTION_REASONS."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class SigningKey:
    """HMAC-SHA256 key for model metadata. Never stored on the model volume."""

    def __init__(self, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ConfigError(f"model signing key must be at least {MIN_KEY_BYTES} bytes")
        self._key = key

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SigningKey:
        env = os.environ if env is None else env
        path = env.get("MODEL_SIGNING_KEY_FILE", "").strip()
        inline = env.get("MODEL_SIGNING_KEY", "").strip()
        if path and inline:
            raise ConfigError("set MODEL_SIGNING_KEY_FILE or MODEL_SIGNING_KEY, not both")
        if path:
            try:
                key = Path(path).read_bytes().strip()
            except OSError as exc:
                raise ConfigError(f"MODEL_SIGNING_KEY_FILE {path!r} unreadable: {exc}") from None
        elif inline:
            key = inline.encode()
        else:
            raise ConfigError(
                "MODEL_SIGNING_KEY_FILE is not set: the flow worker will not load or store"
                " models without a signing key from a Secret"
            )
        return cls(key)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, _SIGNATURE_CONTEXT + payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass(frozen=True)
class ModelMetadata:
    version: str
    created_at: str  # ISO-8601 UTC, "YYYY-MM-DDTHH:MM:SSZ"
    feature_names: tuple[str, ...]
    training_windows: int
    threshold: float
    metrics: dict[str, float] = field(default_factory=dict)
    healthy: bool = False
    window_seconds: int = 600
    sklearn_version: str = sklearn.__version__
    # SHA-256 of the exact .joblib bytes; covered by the signature.
    artifact_sha256: str = ""

    @property
    def created_unix(self) -> int:
        return calendar.timegm(time.strptime(self.created_at, "%Y-%m-%dT%H:%M:%SZ"))


def new_version(now: float | None = None) -> str:
    return "v" + time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() if now is None else now))


def _canonical(body: Mapping[str, Any]) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _check_version(version: str) -> str:
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ModelRejectedError("bad_pointer", f"invalid model version {version!r}")
    return version


def _read_regular(path: Path, limit: int) -> bytes:
    """Read a regular file without following a symlink at its last component."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        raise ModelRejectedError("missing", f"{path.name} does not exist") from None
    except OSError as exc:  # ELOOP for a symlink, EACCES, ...
        raise ModelRejectedError("bad_file", f"{path.name} cannot be opened: {exc}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ModelRejectedError("bad_file", f"{path.name} is not a regular file")
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ModelRejectedError("bad_file", f"{path.name} is larger than {limit} bytes")
    return data


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fsync_dir(path.parent)


def _metadata_from(raw: Mapping[str, Any]) -> ModelMetadata:
    try:
        metrics = raw["metrics"]
        if not isinstance(metrics, dict):
            raise TypeError("metrics")
        names = raw["feature_names"]
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise TypeError("feature_names")
        if not isinstance(raw["healthy"], bool):
            raise TypeError("healthy")
        meta = ModelMetadata(
            version=str(raw["version"]),
            created_at=str(raw["created_at"]),
            feature_names=tuple(names),
            training_windows=int(raw["training_windows"]),
            threshold=float(raw["threshold"]),
            metrics={str(k): float(v) for k, v in metrics.items()},
            healthy=raw["healthy"],
            window_seconds=int(raw["window_seconds"]),
            sklearn_version=str(raw["sklearn_version"]),
            artifact_sha256=str(raw["artifact_sha256"]),
        )
        _ = meta.created_unix  # validates the timestamp format
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelRejectedError("bad_metadata", f"metadata field invalid: {exc}") from None
    return meta


class ModelStore:
    def __init__(self, root: str | Path, key: SigningKey) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._key = key
        self.last_rejection: str | None = None

    def _path(self, version: str, suffix: str) -> Path:
        return self.root / f"{_PREFIX}{_check_version(version)}{suffix}"

    # ── writing ──────────────────────────────────────────────────────────

    def save(self, model: FlowAnomalyModel, meta: ModelMetadata) -> ModelMetadata:
        """Persist artifact + signed metadata. Never touches ``latest``."""
        if model.version != meta.version:
            raise ValueError(f"model version {model.version!r} != metadata {meta.version!r}")
        try:
            artifact, meta_path = (
                self._path(meta.version, ".joblib"),
                self._path(meta.version, ".json"),
            )
        except ModelRejectedError as exc:
            raise ModelStoreError(str(exc)) from None
        if artifact.exists() or meta_path.exists():
            raise ModelStoreError(f"model {meta.version} already exists; artifacts are immutable")
        buf = io.BytesIO()
        joblib.dump(model.forest, buf)
        data = buf.getvalue()
        meta = dataclasses.replace(meta, artifact_sha256=hashlib.sha256(data).hexdigest())
        body = dataclasses.asdict(meta)
        body["signature"] = self._key.sign(_canonical(body))
        try:
            _write_atomic(artifact, data)
            _write_atomic(meta_path, json.dumps(body, indent=2, sort_keys=True).encode())
        except OSError as exc:
            raise ModelStoreError(f"cannot write model {meta.version}: {exc}") from exc
        return meta

    def promote(self, version: str) -> None:
        """Point ``latest`` at ``version`` after re-verifying it is signed,
        intact and healthy."""
        meta = self._verified_metadata(version)
        if not meta.healthy:
            raise ModelRejectedError("unhealthy", f"model {version} did not pass the health gate")
        data = _read_regular(self._path(version, ".joblib"), MAX_ARTIFACT_BYTES)
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), meta.artifact_sha256):
            raise ModelRejectedError(
                "digest_mismatch", f"model {version} artifact changed since save"
            )
        try:
            _write_atomic(self.root / "latest", version.encode())
        except OSError as exc:
            raise ModelStoreError(f"cannot write latest pointer: {exc}") from exc

    def prune(self, keep: int = 5) -> int:
        """Keep ``latest`` plus the newest versions up to ``keep`` in total."""
        latest = self._pointer_or_none()
        versions = self.versions()
        others = [v for v in versions if v != latest]
        budget = max(0, keep - (1 if latest in versions else 0))
        doomed = others[: max(0, len(others) - budget)]
        for path in [self._path(v, sfx) for v in doomed for sfx in (".joblib", ".json")] + list(
            self.root.glob(f".{_PREFIX}*.tmp")
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:  # e.g. a directory planted under that name
                log.warning("cannot prune %s: %s", path.name, exc)
        return len(doomed)

    # ── reading ──────────────────────────────────────────────────────────

    def versions(self) -> list[str]:
        """Versions with a well-formed name (anything else is never loaded)."""
        found = set()
        for p in self.root.iterdir():
            name = p.name
            for suffix in (".json", ".joblib"):
                if name.startswith(_PREFIX) and name.endswith(suffix):
                    v = name[len(_PREFIX) : -len(suffix)]
                    if VERSION_RE.fullmatch(v):
                        found.add(v)
        return sorted(found)

    def latest_version(self) -> str | None:
        """The validated ``latest`` pointer, or None (absent or invalid)."""
        try:
            return self._pointer()
        except ModelRejectedError as exc:
            self._reject(exc)
            return None

    def _pointer(self) -> str | None:
        try:
            raw = _read_regular(self.root / "latest", 64)
        except ModelRejectedError as exc:
            if exc.reason == "missing":
                return None
            raise ModelRejectedError("bad_pointer", f"latest pointer unusable: {exc}") from None
        try:
            version = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ModelRejectedError("bad_pointer", "latest pointer is not ASCII") from None
        return _check_version(version)

    def _pointer_or_none(self) -> str | None:
        try:
            return self._pointer()
        except ModelRejectedError:
            return None

    def _verified_metadata(self, version: str) -> ModelMetadata:
        raw_bytes = _read_regular(self._path(version, ".json"), MAX_METADATA_BYTES)
        try:
            raw = json.loads(raw_bytes)
        except ValueError:
            raise ModelRejectedError(
                "bad_metadata", f"model {version} metadata is not JSON"
            ) from None
        if not isinstance(raw, dict):
            raise ModelRejectedError("bad_metadata", f"model {version} metadata is not an object")
        signature = raw.pop("signature", None)
        if not isinstance(signature, str) or not signature:
            raise ModelRejectedError("unsigned", f"model {version} metadata carries no signature")
        try:
            payload = _canonical(raw)
        except (TypeError, ValueError):
            raise ModelRejectedError("bad_metadata", f"model {version} metadata invalid") from None
        if not self._key.verify(payload, signature):
            raise ModelRejectedError(
                "bad_signature",
                f"model {version} metadata signature does not verify (tampered, or signed"
                " with another key)",
            )
        meta = _metadata_from(raw)
        if meta.version != version:
            raise ModelRejectedError("bad_metadata", f"metadata of {version} names {meta.version}")
        if not re.fullmatch(r"[0-9a-f]{64}", meta.artifact_sha256):
            raise ModelRejectedError("unsigned", f"model {version} metadata carries no digest")
        return meta

    def load(
        self, version: str | None = None, window_seconds: int | None = None
    ) -> tuple[FlowAnomalyModel, ModelMetadata] | None:
        """Load a verified, healthy, compatible model (default: ``latest``).

        Returns None when there is none; the reason of a refusal is logged
        and kept in ``last_rejection``.
        """
        self.last_rejection = None
        try:
            if version is None:
                version = self._pointer()
                if version is None:
                    return None
            return self._load(_check_version(version), window_seconds)
        except ModelRejectedError as exc:
            self._reject(exc)
            return None

    def _load(
        self, version: str, window_seconds: int | None
    ) -> tuple[FlowAnomalyModel, ModelMetadata]:
        meta = self._verified_metadata(version)
        if not meta.healthy:
            raise ModelRejectedError("unhealthy", f"model {version} did not pass the health gate")
        if tuple(meta.feature_names) != FEATURE_NAMES:
            raise ModelRejectedError("incompatible", f"model {version} has other features")
        if window_seconds is not None and meta.window_seconds != window_seconds:
            raise ModelRejectedError(
                "incompatible",
                f"model {version} was trained on {meta.window_seconds}s windows, not"
                f" {window_seconds}s",
            )
        if meta.sklearn_version != sklearn.__version__:
            raise ModelRejectedError(
                "incompatible",
                f"model {version} was pickled by scikit-learn {meta.sklearn_version}, this is"
                f" {sklearn.__version__}",
            )
        data = _read_regular(self._path(version, ".joblib"), MAX_ARTIFACT_BYTES)
        actual = hashlib.sha256(data).hexdigest()
        if not hmac.compare_digest(actual, meta.artifact_sha256):
            raise ModelRejectedError(
                "digest_mismatch",
                f"model {version} artifact digest {actual} does not match the signed"
                f" {meta.artifact_sha256}",
            )
        # Only now, and only these verified bytes.
        try:
            forest = joblib.load(io.BytesIO(data))
        except Exception as exc:
            raise ModelRejectedError("unpickle_failed", f"model {version}: {exc!r}") from None
        if not isinstance(forest, IsolationForest) or getattr(
            forest, "n_features_in_", None
        ) != len(FEATURE_NAMES):
            raise ModelRejectedError("unpickle_failed", f"model {version} is not a fitted forest")
        return FlowAnomalyModel(version=version, forest=forest), meta

    def _reject(self, exc: ModelRejectedError) -> None:
        self.last_rejection = exc.reason
        level = logging.WARNING if exc.reason in ("unhealthy", "incompatible") else logging.ERROR
        log.log(level, "refusing model: %s (reason=%s)", exc, exc.reason)
