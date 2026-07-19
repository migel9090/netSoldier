"""Model evaluation with synthetic attack injection (step 114).

There are no labeled attacks in home traffic, so evaluation works from
two directions:

- **FP rate**: score a held-out slice of presumed-normal history; every
  window at/above threshold is counted as a false positive.
- **Detection rate** (1 - FN rate): inject synthetic attack windows whose
  shapes are scaled off the baseline's own percentiles (exfil upload,
  scan fan-out, connection storm) and check the model flags them.

Synthetic injection is relative, not absolute: an "exfil" is defined as
~50x the baseline's p99 upload, so evaluation stays meaningful whether
the household's normal is 10 MB or 10 GB per window.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from statistics import quantiles
from typing import TYPE_CHECKING

from ml_anomaly.flows import FlowWindow

if TYPE_CHECKING:
    from ml_anomaly.iforest import FlowAnomalyModel

# Below these the model is not trustworthy enough to promote (metadata
# healthy=False): >5% FP would spam the approval queue, <80% detection
# on caricature attacks means the baseline swallowed the signal.
MAX_HEALTHY_FP_RATE = 0.05
MIN_HEALTHY_DETECTION_RATE = 0.8


@dataclass(frozen=True)
class EvalMetrics:
    fp_rate: float
    detection_rate: float
    holdout_windows: int
    injected_anomalies: int
    threshold: float

    @property
    def healthy(self) -> bool:
        return (
            self.fp_rate <= MAX_HEALTHY_FP_RATE
            and self.detection_rate >= MIN_HEALTHY_DETECTION_RATE
        )

    def as_dict(self) -> dict[str, float]:
        return {
            "fp_rate": round(self.fp_rate, 4),
            "detection_rate": round(self.detection_rate, 4),
            "holdout_windows": float(self.holdout_windows),
            "injected_anomalies": float(self.injected_anomalies),
            "threshold": self.threshold,
        }


def _p99(values: list[float]) -> float:
    if not values:
        return 0.0
    if len(values) < 10:
        return max(values)
    return quantiles(values, n=100)[98]


def inject_anomalies(
    baseline: list[FlowWindow], per_pattern: int = 10, seed: int = 1337
) -> list[FlowWindow]:
    """Synthetic attack windows scaled off the baseline's percentiles."""
    rng = random.Random(seed)  # noqa: S311 — jitter for synthetic eval data, not crypto
    p99_out = max(1.0, _p99([float(w.bytes_out) for w in baseline]))
    p99_conn = max(1.0, _p99([float(w.conn_count) for w in baseline]))
    p99_dst = max(1.0, _p99([float(w.dst_fanout) for w in baseline]))

    def jitter(v: float) -> int:
        return max(1, int(v * rng.uniform(0.8, 1.5)))

    anomalies: list[FlowWindow] = []
    for i in range(per_pattern):
        ts = f"2026-01-01 {i % 24:02d}:00:00"  # placeholder; not a feature
        # exfil: sustained upload dwarfing the household's biggest normal
        anomalies.append(
            FlowWindow(
                src_ip="192.168.99.1",
                window_start=ts,
                conn_count=jitter(5),
                bytes_out=jitter(p99_out * 50),
                bytes_in=jitter(p99_out * 0.01),
                dst_fanout=jitter(2),
                port_fanout=1,
                avg_duration_ms=jitter(300_000),
            )
        )
        # scan: destination/port fan-out storm of tiny connections
        anomalies.append(
            FlowWindow(
                src_ip="192.168.99.2",
                window_start=ts,
                conn_count=jitter(p99_conn * 30),
                bytes_out=jitter(p99_out * 0.05),
                bytes_in=jitter(p99_out * 0.01),
                dst_fanout=jitter(p99_dst * 25),
                port_fanout=jitter(500),
                avg_duration_ms=jitter(10),
            )
        )
        # connection storm: volume in both directions, one destination
        anomalies.append(
            FlowWindow(
                src_ip="192.168.99.3",
                window_start=ts,
                conn_count=jitter(p99_conn * 50),
                bytes_out=jitter(p99_out * 20),
                bytes_in=jitter(p99_out * 20),
                dst_fanout=jitter(2),
                port_fanout=jitter(2),
                avg_duration_ms=jitter(50),
            )
        )
    return anomalies


def evaluate(
    model: FlowAnomalyModel,
    holdout: list[FlowWindow],
    threshold: float,
    per_pattern: int = 10,
    seed: int = 1337,
) -> EvalMetrics:
    injected = inject_anomalies(holdout, per_pattern=per_pattern, seed=seed)
    holdout_scores = model.scores(holdout)
    injected_scores = model.scores(injected)
    fp = sum(1 for s in holdout_scores if s >= threshold)
    caught = sum(1 for s in injected_scores if s >= threshold)
    return EvalMetrics(
        fp_rate=fp / len(holdout) if holdout else 0.0,
        detection_rate=caught / len(injected) if injected else 0.0,
        holdout_windows=len(holdout),
        injected_anomalies=len(injected),
        threshold=threshold,
    )
