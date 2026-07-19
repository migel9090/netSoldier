"""Unit tests for the Isolation Forest flow anomaly model (step 113)."""

import pytest
from ml_anomaly.iforest import (
    MAX_CONFIDENCE,
    MIN_CONFIDENCE,
    MIN_TRAINING_WINDOWS,
    FlowAnomalyModel,
    dominant_tags,
    score_to_confidence,
    score_to_severity,
)

from tests.fixtures import baseline_windows as _baseline_windows
from tests.fixtures import exfil_window as _exfil_window
from tests.fixtures import scan_window as _scan_window


def test_fit_requires_minimum_baseline():
    with pytest.raises(ValueError, match="baseline windows"):
        FlowAnomalyModel.fit(_baseline_windows(MIN_TRAINING_WINDOWS - 1), "t")


def test_outliers_score_above_baseline():
    model = FlowAnomalyModel.fit(_baseline_windows(), version="test-1")
    baseline_scores = model.scores(_baseline_windows(n=50, seed=99))
    outlier_scores = model.scores([_exfil_window(), _scan_window()])
    assert max(outlier_scores) > max(baseline_scores)
    assert all(s > 0.6 for s in outlier_scores)


def test_detect_flags_only_outliers():
    model = FlowAnomalyModel.fit(_baseline_windows(), version="test-1")
    windows = [*_baseline_windows(n=30, seed=99), _exfil_window()]
    anomalies = model.detect(windows, threshold=0.65)
    assert any(a.src_ip == "192.168.1.66" for a in anomalies)
    top = anomalies[0]
    assert top.src_ip == "192.168.1.66"
    assert top.model_version == "test-1"
    assert MIN_CONFIDENCE <= top.confidence <= MAX_CONFIDENCE
    # baseline traffic mostly stays quiet
    assert len(anomalies) <= 3


def test_determinism_across_refits():
    a = FlowAnomalyModel.fit(_baseline_windows(), version="a")
    b = FlowAnomalyModel.fit(_baseline_windows(), version="b")
    assert a.scores([_exfil_window()]) == b.scores([_exfil_window()])


def test_confidence_never_reaches_auto_enforce():
    # 80 is the auto-enforce line; a lone volumetric anomaly must stay under
    assert score_to_confidence(1.0) == MAX_CONFIDENCE == 70
    assert score_to_confidence(0.65) == MIN_CONFIDENCE
    assert score_to_confidence(0.0) == MIN_CONFIDENCE
    mid = score_to_confidence(0.825)
    assert MIN_CONFIDENCE < mid < MAX_CONFIDENCE


def test_severity_buckets():
    assert score_to_severity(0.9) == "high"
    assert score_to_severity(0.8) == "medium"
    assert score_to_severity(0.7) == "low"


def test_dominant_tags_explain_shape():
    exfil_tags = dominant_tags(_exfil_window())
    assert "upload-heavy" in exfil_tags
    scan_tags = dominant_tags(_scan_window())
    assert "dst-fanout" in scan_tags
    assert "port-fanout" in scan_tags
