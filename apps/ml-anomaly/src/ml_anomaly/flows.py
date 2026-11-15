"""Flow feature extraction for volumetric/exfil anomaly detection (steps 113, 125.23).

EXPERIMENTAL: the volumetric signal works end to end, but its calibration
(score -> confidence, health gate, poisoning resistance) is roadmap step 129.
Treat its rows as a hint for a human, not as evidence.

Flows come from Zeek's ``conn.log`` (``netsoldier.zeek_conn``), which records
originator and responder explicitly. Each window aggregates the connections a
source *originated*: ``bytes_out`` is what the originator sent
(``orig_bytes``), ``bytes_in`` what it received (``resp_bytes``). How rows are
placed into windows (by arrival, so long flows count) is described in
:meth:`ml_anomaly.clickhouse.ClickHouseClient.fetch_flow_windows`.

Everything here is pure and unit-tested; ClickHouse I/O lives in
:mod:`ml_anomaly.clickhouse`.
"""

from __future__ import annotations

import ipaddress
import math
import time
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
    window_start: str  # "YYYY-MM-DD HH:MM:SS", UTC
    conn_count: int
    bytes_out: int
    bytes_in: int
    dst_fanout: int
    port_fanout: int
    avg_duration_ms: float
    # rows placed in this window because they arrived more than the allowed
    # lateness after they ended (e.g. a backlog flushed after an outage)
    late_rows: int = 0


def utc_text(ts: int) -> str:
    """Unix seconds -> 'YYYY-MM-DD HH:MM:SS' in UTC."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts))


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
