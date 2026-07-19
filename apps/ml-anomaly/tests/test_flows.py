"""Unit tests for flow feature extraction (step 113)."""

import math

from ml_anomaly.flows import (
    FEATURE_NAMES,
    FlowWindow,
    internal_only,
    is_internal,
    to_matrix,
    to_vector,
)


def _window(**overrides) -> FlowWindow:
    base = {
        "src_ip": "192.168.1.50",
        "window_start": "2026-07-19 12:00:00",
        "conn_count": 20,
        "bytes_out": 100_000,
        "bytes_in": 2_000_000,
        "dst_fanout": 5,
        "port_fanout": 3,
        "avg_duration_ms": 1500.0,
    }
    base.update(overrides)
    return FlowWindow(**base)


def test_is_internal():
    assert is_internal("192.168.1.50")
    assert is_internal("10.0.0.7")
    assert is_internal("fd00::1")
    assert not is_internal("203.0.113.99")
    assert not is_internal("not-an-ip")
    assert not is_internal("")


def test_internal_only_filters_public_sources():
    windows = [_window(), _window(src_ip="203.0.113.99")]
    kept = internal_only(windows)
    assert len(kept) == 1
    assert kept[0].src_ip == "192.168.1.50"


def test_vector_matches_feature_names():
    vec = to_vector(_window())
    assert len(vec) == len(FEATURE_NAMES)
    assert vec[0] == math.log1p(100_000)  # log_bytes_out
    assert vec[1] == math.log1p(2_000_000)  # log_bytes_in
    assert vec[2] == math.log1p(20)  # log_conn_count


def test_vector_clamps_negative_inputs():
    vec = to_vector(_window(bytes_out=-5, avg_duration_ms=-1.0))
    assert vec[0] == 0.0
    assert vec[-1] == 0.0


def test_matrix_shape():
    m = to_matrix([_window(), _window(src_ip="192.168.1.51")])
    assert len(m) == 2
    assert all(len(row) == len(FEATURE_NAMES) for row in m)
