"""Unit tests for model evaluation with synthetic injection (step 114)."""

from ml_anomaly.evaluate import (
    MAX_HEALTHY_FP_RATE,
    MIN_HEALTHY_DETECTION_RATE,
    EvalMetrics,
    evaluate,
    inject_anomalies,
)
from ml_anomaly.iforest import FlowAnomalyModel

from tests.fixtures import baseline_windows as _baseline_windows


def test_injected_anomalies_scale_with_baseline():
    baseline = _baseline_windows()
    injected = inject_anomalies(baseline, per_pattern=5, seed=1)
    assert len(injected) == 15  # 3 patterns x 5
    p99_out = sorted(w.bytes_out for w in baseline)[int(len(baseline) * 0.99) - 1]
    exfil = [w for w in injected if w.src_ip == "192.168.99.1"]
    assert all(w.bytes_out > 10 * p99_out for w in exfil)
    scans = [w for w in injected if w.src_ip == "192.168.99.2"]
    assert all(w.dst_fanout > 50 for w in scans)


def test_injection_is_deterministic_per_seed():
    baseline = _baseline_windows()
    assert inject_anomalies(baseline, seed=5) == inject_anomalies(baseline, seed=5)
    assert inject_anomalies(baseline, seed=5) != inject_anomalies(baseline, seed=6)


def test_trained_model_evaluates_healthy():
    model = FlowAnomalyModel.fit(_baseline_windows(), version="t")
    holdout = _baseline_windows(n=60, seed=99)
    metrics = evaluate(model, holdout, threshold=0.65)
    assert metrics.detection_rate >= MIN_HEALTHY_DETECTION_RATE
    assert metrics.fp_rate <= MAX_HEALTHY_FP_RATE
    assert metrics.healthy
    assert metrics.holdout_windows == 60


def test_unhealthy_when_threshold_absurd():
    model = FlowAnomalyModel.fit(_baseline_windows(), version="t")
    holdout = _baseline_windows(n=60, seed=99)
    # threshold below every normal score -> everything is an "anomaly"
    metrics = evaluate(model, holdout, threshold=0.1)
    assert metrics.fp_rate > MAX_HEALTHY_FP_RATE
    assert not metrics.healthy


def test_metrics_as_dict_rounds():
    m = EvalMetrics(
        fp_rate=0.03333333,
        detection_rate=0.966666,
        holdout_windows=60,
        injected_anomalies=30,
        threshold=0.65,
    )
    d = m.as_dict()
    assert d["fp_rate"] == 0.0333
    assert d["detection_rate"] == 0.9667
