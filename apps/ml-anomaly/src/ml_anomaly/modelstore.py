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
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from ml_anomaly.iforest import FlowAnomalyModel

_PREFIX = "iforest-"


@dataclass(frozen=True)
class ModelMetadata:
    version: str
    created_at: str  # ISO-8601 UTC
    feature_names: tuple[str, ...]
    training_windows: int
    threshold: float
    metrics: dict[str, float] = field(default_factory=dict)
    healthy: bool = True


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
        joblib.dump(model.forest, self.root / f"{_PREFIX}{meta.version}.joblib")
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
            forest = joblib.load(forest_path)
            raw = json.loads(meta_path.read_text())
            meta = ModelMetadata(
                version=str(raw["version"]),
                created_at=str(raw["created_at"]),
                feature_names=tuple(raw["feature_names"]),
                training_windows=int(raw["training_windows"]),
                threshold=float(raw["threshold"]),
                metrics={k: float(v) for k, v in raw.get("metrics", {}).items()},
                healthy=bool(raw.get("healthy", True)),
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
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
