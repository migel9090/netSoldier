"""Versioned persistence for flow anomaly models (step 114).

Layout under MODEL_DIR:

    iforest-v20260719120000.joblib   # the fitted sklearn forest
    iforest-v20260719120000.json     # metadata: features, eval metrics
    latest                           # file containing the current version

Artifacts are immutable once written; ``latest`` is the only mutable
pointer, so a half-written artifact can never become current.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from ml_anomaly.iforest import FlowAnomalyModel

log = logging.getLogger("ml_anomaly.modelstore")

_PREFIX = "iforest-"


def _digest(path: Path) -> str:
    """SHA-256 of an artifact file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class ModelMetadata:
    version: str
    created_at: str  # ISO-8601 UTC
    feature_names: tuple[str, ...]
    training_windows: int
    threshold: float
    metrics: dict[str, float] = field(default_factory=dict)
    healthy: bool = True
    # SHA-256 of the .joblib artifact.
    #
    # joblib.load() unpickles, which executes arbitrary code in the serving
    # process. The artifact lives on a shared PVC and the API reloads it
    # whenever `latest` changes, so anything able to write to that volume
    # could get code execution in a pod that holds ClickHouse credentials.
    # Recording the digest alongside the metadata means load() can refuse an
    # artifact that is not the one the training job wrote. It is not a
    # signature — it does not help if an attacker can rewrite both files —
    # but it closes the "swap just the model blob" case and makes silent
    # corruption loud.
    artifact_sha256: str = ""


def new_version() -> str:
    return "v" + time.strftime("%Y%m%d%H%M%S", time.gmtime())


class ModelStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, model: FlowAnomalyModel, meta: ModelMetadata) -> None:
        """Persist artifact + metadata, then flip ``latest``."""
        if model.version != meta.version:
            raise ValueError(
                f"model version {model.version!r} != metadata {meta.version!r}"
            )
        forest_path = self.root / f"{_PREFIX}{meta.version}.joblib"
        joblib.dump(model.forest, forest_path)

        # Record the digest of what we just wrote so load() can verify it.
        meta = dataclasses.replace(meta, artifact_sha256=_digest(forest_path))

        meta_path = self.root / f"{_PREFIX}{meta.version}.json"
        meta_path.write_text(json.dumps(dataclasses.asdict(meta), indent=2))
        # write-then-rename so `latest` is always a complete pointer
        tmp = self.root / "latest.tmp"
        tmp.write_text(meta.version)
        tmp.replace(self.root / "latest")

    def latest_version(self) -> str | None:
        pointer = self.root / "latest"
        if not pointer.exists():
            return None
        version = pointer.read_text().strip()
        return version or None

    def load(self, version: str | None = None) -> tuple[FlowAnomalyModel, ModelMetadata] | None:
        """Load a version (default: latest). None when absent/corrupt —
        callers fall back to an ad-hoc fit rather than crash-looping."""
        version = version or self.latest_version()
        if version is None:
            return None
        forest_path = self.root / f"{_PREFIX}{version}.joblib"
        meta_path = self.root / f"{_PREFIX}{version}.json"
        if not forest_path.exists() or not meta_path.exists():
            return None
        try:
            raw = json.loads(meta_path.read_text())
            meta = ModelMetadata(
                version=str(raw["version"]),
                created_at=str(raw["created_at"]),
                feature_names=tuple(raw["feature_names"]),
                training_windows=int(raw["training_windows"]),
                threshold=float(raw["threshold"]),
                metrics={k: float(v) for k, v in raw.get("metrics", {}).items()},
                healthy=bool(raw.get("healthy", True)),
                artifact_sha256=str(raw.get("artifact_sha256", "")),
            )

            # Verify BEFORE unpickling: joblib.load executes code, so the
            # check is worthless if it runs afterwards.
            if meta.artifact_sha256:
                actual = _digest(forest_path)
                if actual != meta.artifact_sha256:
                    log.error(
                        "refusing model %s: artifact digest %s does not match "
                        "metadata %s — the .joblib was replaced or corrupted",
                        version,
                        actual,
                        meta.artifact_sha256,
                    )
                    return None
            else:
                # Artifacts written before step 124 carry no digest. Serve
                # them (refusing would take detection offline on upgrade) but
                # say so, because an unverified artifact is a trust gap.
                log.warning(
                    "model %s has no artifact_sha256; it cannot be verified. "
                    "Re-run training to record one.",
                    version,
                )

            forest = joblib.load(forest_path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            log.warning("model %s could not be loaded: %s", version, exc)
            return None
        return FlowAnomalyModel(version=version, forest=forest), meta

    def versions(self) -> list[str]:
        return sorted(
            p.stem.removeprefix(_PREFIX)
            for p in self.root.glob(f"{_PREFIX}*.json")
        )

    def prune(self, keep: int = 5) -> int:
        """Drop oldest artifacts beyond ``keep``; never drops latest."""
        latest = self.latest_version()
        candidates = [v for v in self.versions() if v != latest]
        excess = len(candidates) - max(0, keep - (1 if latest else 0))
        removed = 0
        for version in candidates[:max(0, excess)]:
            for suffix in (".joblib", ".json"):
                path = self.root / f"{_PREFIX}{version}{suffix}"
                if path.exists():
                    path.unlink()
            removed += 1
        return removed
