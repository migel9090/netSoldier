"""Isolation Forest over flow windows (step 113).

Detects volumetric anomalies — exfiltration-sized uploads, connection
storms, destination fan-out — as deviations from the household's own
baseline, without labels or thresholds per device.

Scores follow the Liu et al. convention exposed by scikit-learn's
``score_samples`` (negated): 0..1, where ~0.5 is unremarkable and values
approaching 1 are strongly isolated. A lone volumetric anomaly is capped
at confidence 70, below beacons (75) and well below the 80 auto-enforce
line — composite-confidence (step 116) is what escalates it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sklearn.ensemble import IsolationForest

from ml_anomaly.flows import FEATURE_NAMES, FlowWindow, to_matrix

# Windows scoring below this are not worth a row; the ceiling of normal
# traffic sits around 0.55-0.6 on home baselines.
DEFAULT_SCORE_THRESHOLD = 0.65

# A single-signal volumetric anomaly must not auto-enforce on its own.
MAX_CONFIDENCE = 70
MIN_CONFIDENCE = 40

# Below this many baseline windows the forest just memorizes noise.
MIN_TRAINING_WINDOWS = 50


@dataclass(frozen=True)
class FlowAnomaly:
    """One anomalous window, ready to serialize into ml_anomalies."""

    src_ip: str
    window_start: str
    anomaly_score: float
    confidence: int
    severity: str
    conn_count: int
    bytes_out: int
    bytes_in: int
    dst_fanout: int
    port_fanout: int
    avg_duration_ms: float
    model_version: str
    tags: tuple[str, ...] = field(default_factory=tuple)


def score_to_confidence(
    score: float, threshold: float = DEFAULT_SCORE_THRESHOLD
) -> int:
    """Linear map from [threshold..1.0] onto [MIN..MAX] confidence."""
    if score <= threshold:
        return MIN_CONFIDENCE
    if score >= 1.0:
        return MAX_CONFIDENCE
    span = 1.0 - threshold
    frac = (score - threshold) / span
    return round(MIN_CONFIDENCE + frac * (MAX_CONFIDENCE - MIN_CONFIDENCE))


def score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.75:
        return "medium"
    return "low"


def dominant_tags(w: FlowWindow) -> tuple[str, ...]:
    """Human-readable hints about *why* a window looks odd, so the alert
    and the incident view can say more than "the forest said so"."""
    tags = ["anomaly", "iforest"]
    if w.bytes_out > 0 and w.bytes_out >= 10 * max(1, w.bytes_in):
        tags.append("upload-heavy")
    if w.dst_fanout >= 50:
        tags.append("dst-fanout")
    if w.port_fanout >= 50:
        tags.append("port-fanout")
    return tuple(tags)


class FlowAnomalyModel:
    """Thin, deterministic wrapper around ``IsolationForest``."""

    def __init__(self, version: str, forest: IsolationForest) -> None:
        self.version = version
        self.forest = forest
        self.feature_names = FEATURE_NAMES

    @classmethod
    def fit(cls, windows: list[FlowWindow], version: str) -> FlowAnomalyModel:
        if len(windows) < MIN_TRAINING_WINDOWS:
            raise ValueError(
                f"need >={MIN_TRAINING_WINDOWS} baseline windows, got {len(windows)}"
            )
        forest = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42,  # deterministic across refits on same data
            n_jobs=1,
        )
        forest.fit(to_matrix(windows))
        return cls(version=version, forest=forest)

    def scores(self, windows: list[FlowWindow]) -> list[float]:
        """Anomaly score 0..1 per window (1 = most isolated)."""
        if not windows:
            return []
        # cast off np.float64 so downstream json.dumps stays happy
        return [float(-s) for s in self.forest.score_samples(to_matrix(windows))]

    def detect(
        self,
        windows: list[FlowWindow],
        threshold: float = DEFAULT_SCORE_THRESHOLD,
    ) -> list[FlowAnomaly]:
        """Score windows and keep those at/above threshold, highest first."""
        anomalies: list[FlowAnomaly] = []
        for w, score in zip(windows, self.scores(windows), strict=True):
            if score < threshold:
                continue
            anomalies.append(
                FlowAnomaly(
                    src_ip=w.src_ip,
                    window_start=w.window_start,
                    anomaly_score=round(score, 4),
                    confidence=score_to_confidence(score, threshold),
                    severity=score_to_severity(score),
                    conn_count=w.conn_count,
                    bytes_out=w.bytes_out,
                    bytes_in=w.bytes_in,
                    dst_fanout=w.dst_fanout,
                    port_fanout=w.port_fanout,
                    avg_duration_ms=round(w.avg_duration_ms, 1),
                    model_version=self.version,
                    tags=dominant_tags(w),
                )
            )
        anomalies.sort(key=lambda a: a.anomaly_score, reverse=True)
        return anomalies
