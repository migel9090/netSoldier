"""Flow feature extraction for volumetric/exfil anomaly detection (step 113).

The detection-engine correlator writes one ``connections`` row per flow
(who→where→how much). This module aggregates those rows into per-source
time windows and turns each window into a numeric feature vector for the
Isolation Forest in :mod:`ml_anomaly.iforest`.

Everything here is pure and unit-tested; ClickHouse I/O lives in
:mod:`ml_anomaly.clickhouse`.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass

# Feature order is part of the model contract: a persisted model is only
# valid for vectors built with the same names in the same order.
FEATURE_NAMES: tuple[str, ...] = (
    "log_bytes_out",
    "log_bytes_in",
    "log_conn_count",
    "log_dst_fanout",
    "log_port_fanout",
    "log_avg_duration_ms",
)


@dataclass(frozen=True)
class FlowWindow:
    """Aggregated flow activity of one source IP over one time window."""

    src_ip: str
    window_start: str  # "YYYY-MM-DD HH:MM:SS" (ClickHouse DateTime text)
    conn_count: int
    bytes_out: int
    bytes_in: int
    dst_fanout: int
    port_fanout: int
    avg_duration_ms: float


# Mirrors detection-engine's DefaultLocalCIDRs: explicit RFC1918 + ULA +
# loopback + link-local. Deliberately NOT ipaddress.is_private — since
# Python 3.12.4 that also covers TEST-NET/benchmarking ranges, which are
# not "our devices".
_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def is_internal(addr: str) -> bool:
    """Only local devices get anomaly-scored; scanners on the internet side
    are someone else's problem and would drown the baseline."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in _LOCAL_NETWORKS)


def to_vector(w: FlowWindow) -> list[float]:
    """Feature vector for one window.

    Byte/count features span many orders of magnitude (an idle sensor vs a
    4K stream), so everything is log1p-compressed; without it the forest
    splits almost exclusively on raw byte volume.
    """
    return [
        math.log1p(max(0, w.bytes_out)),
        math.log1p(max(0, w.bytes_in)),
        math.log1p(max(0, w.conn_count)),
        math.log1p(max(0, w.dst_fanout)),
        math.log1p(max(0, w.port_fanout)),
        math.log1p(max(0.0, w.avg_duration_ms)),
    ]


def to_matrix(windows: list[FlowWindow]) -> list[list[float]]:
    return [to_vector(w) for w in windows]


def internal_only(windows: list[FlowWindow]) -> list[FlowWindow]:
    return [w for w in windows if is_internal(w.src_ip)]
