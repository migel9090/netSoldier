"""Shared synthetic traffic fixtures for the flow-anomaly tests."""

import random

from ml_anomaly.flows import FlowWindow


def baseline_windows(n: int = 200, seed: int = 7) -> list[FlowWindow]:
    """Synthetic 'normal home' baseline: browsing/streaming-shaped windows
    clustered the way real household traffic is (lognormal volumes)."""
    rng = random.Random(seed)
    windows = []
    for i in range(n):
        windows.append(
            FlowWindow(
                src_ip=f"192.168.1.{50 + i % 5}",
                window_start=f"2026-07-12 {i % 24:02d}:00:00",
                conn_count=max(1, int(rng.gauss(30, 8))),
                bytes_out=max(1_000, int(rng.lognormvariate(12.2, 0.5))),
                bytes_in=max(10_000, int(rng.lognormvariate(15.4, 0.6))),
                dst_fanout=max(1, int(rng.gauss(8, 3))),
                port_fanout=max(1, int(rng.gauss(3, 1))),
                avg_duration_ms=max(50.0, rng.gauss(2_000, 500)),
            )
        )
    return windows


def exfil_window() -> FlowWindow:
    """5 GB pushed out in one window from one device — obvious exfil."""
    return FlowWindow(
        src_ip="192.168.1.66",
        window_start="2026-07-19 03:10:00",
        conn_count=12,
        bytes_out=5_000_000_000,
        bytes_in=80_000,
        dst_fanout=2,
        port_fanout=1,
        avg_duration_ms=590_000.0,
    )


def scan_window() -> FlowWindow:
    """Destination/port fan-out storm — scan or worm behaviour."""
    return FlowWindow(
        src_ip="192.168.1.77",
        window_start="2026-07-19 03:20:00",
        conn_count=2_000,
        bytes_out=400_000,
        bytes_in=120_000,
        dst_fanout=250,
        port_fanout=800,
        avg_duration_ms=8.0,
    )
