"""Unit tests for the RITA beacon → detection mapping (step 112)."""

from ml_anomaly.beacon import (
    BeaconRow,
    build_detection,
    normalize_ip,
    score_to_confidence,
    score_to_severity,
    select_beacons,
)


def test_normalize_ip_strips_v4_mapped_prefix():
    assert normalize_ip("::ffff:192.168.1.50") == "192.168.1.50"
    assert normalize_ip("203.0.113.99") == "203.0.113.99"
    assert normalize_ip("2001:db8::1") == "2001:db8::1"


def test_confidence_capped_below_auto_enforce():
    # even a perfect beacon stays below the 80 auto-enforce threshold
    assert score_to_confidence(1.0) == 75
    assert score_to_confidence(0.996) == 75
    assert score_to_confidence(0.5) == 38
    assert score_to_confidence(0.0) == 0
    # out-of-range inputs are clamped
    assert score_to_confidence(1.5) == 75
    assert score_to_confidence(-0.2) == 0


def test_severity_buckets():
    assert score_to_severity(0.996) == "high"
    assert score_to_severity(0.85) == "medium"
    assert score_to_severity(0.7) == "low"


def test_build_detection_tags_and_domain():
    row = BeaconRow(
        src="::ffff:192.168.1.50",
        dst="::ffff:203.0.113.99",
        beacon_score=0.9963,
        connection_count=180,
        beacon_type="fixed",
        fqdn="c2.evil.example",
    )
    det = build_detection(row)
    assert det.src_ip == "192.168.1.50"
    assert det.dst_ip == "203.0.113.99"
    assert det.beacon_score == 0.9963
    assert det.confidence == 75
    assert det.severity == "high"
    assert det.dst_domain == "c2.evil.example"
    assert "beacon" in det.tags
    assert "beacon:fixed" in det.tags


def test_select_beacons_threshold_and_dedupe():
    rows = [
        # below threshold -> dropped
        BeaconRow("192.168.1.10", "8.8.8.8", 0.5, 10),
        # same pair twice -> keep the higher score
        BeaconRow("192.168.1.50", "203.0.113.99", 0.80, 90),
        BeaconRow("192.168.1.50", "203.0.113.99", 0.99, 180),
        # distinct pair above threshold
        BeaconRow("192.168.1.51", "198.51.100.7", 0.75, 40),
    ]
    out = select_beacons(rows, threshold=0.7)
    assert len(out) == 2
    # sorted by score descending
    assert out[0].dst_ip == "203.0.113.99"
    assert out[0].beacon_score == 0.99
    assert out[0].connection_count == 180
    assert out[1].dst_ip == "198.51.100.7"


def test_select_beacons_empty_when_all_below():
    rows = [BeaconRow("192.168.1.10", "8.8.8.8", 0.4, 10)]
    assert select_beacons(rows, threshold=0.7) == []
