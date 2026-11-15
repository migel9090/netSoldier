"""Worker metrics endpoint and cycle accounting (125.23, audit ML-1)."""

import socket
import urllib.request

import pytest
from ml_anomaly.clickhouse import ClickHouseError
from ml_anomaly.config import ConfigError, env_float
from ml_anomaly.metrics import FAILURE_REASONS, WorkerMetrics


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(m, name, **labels):
    return m.registry.get_sample_value(name, {"worker": m.worker, **labels})


def test_series_exist_before_the_first_cycle():
    m = WorkerMetrics("beacon_sync")
    for reason in FAILURE_REASONS:
        assert _get(m, "ml_anomaly_cycle_failures_total", reason=reason) == 0
    assert _get(m, "ml_anomaly_last_success_timestamp_seconds") == 0
    assert _get(m, "ml_anomaly_clickhouse_up") == 0


def test_metrics_are_served_over_http():
    m = WorkerMetrics("flow_anomaly")
    port = _free_port()
    m.serve(port, addr="127.0.0.1")
    m.run_cycle(lambda: None, clock=lambda: 1234.0)
    url = f"http://127.0.0.1:{port}/metrics"
    body = urllib.request.urlopen(url, timeout=5).read().decode()
    assert 'ml_anomaly_last_success_timestamp_seconds{worker="flow_anomaly"} 1234.0' in body
    assert 'ml_anomaly_cycles_total{outcome="ok",worker="flow_anomaly"} 1.0' in body
    assert "ml_anomaly_cycle_duration_seconds_bucket" in body
    assert "process_resident_memory_bytes" in body


def test_failures_are_classified():
    m = WorkerMetrics("beacon_sync")

    def unreachable():
        raise ClickHouseError("unreachable", "connection refused")

    def bug():
        raise KeyError("oops")

    assert m.run_cycle(unreachable) is False
    assert m.run_cycle(bug) is False
    assert _get(m, "ml_anomaly_cycle_failures_total", reason="unreachable") == 1
    assert _get(m, "ml_anomaly_cycle_failures_total", reason="internal") == 1
    assert _get(m, "ml_anomaly_cycles_total", outcome="failed") == 2
    assert _get(m, "ml_anomaly_last_success_timestamp_seconds") == 0


def test_env_float_rejects_nan():
    with pytest.raises(ConfigError):
        env_float({"X": "nan"}, "X", 1.0, 0.0, 2.0)
