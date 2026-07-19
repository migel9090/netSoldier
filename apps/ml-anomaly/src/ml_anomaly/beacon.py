"""RITA beaconing → netSoldier detection events (roadmap step 112).

RITA imports Zeek conn logs and scores each internal→external pair for
beaconing regularity in ``<db>.threat_mixtape`` (see step 111). This module
turns high-scoring beacons into detection events with a calibrated
confidence, deduplicated per source→destination pair.

The scoring/mapping logic here is pure and unit-tested; the ClickHouse I/O
lives in :mod:`ml_anomaly.clickhouse`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# RITA stores addresses as IPv4-mapped IPv6 ("::ffff:192.168.1.50").
_V4_MAPPED_PREFIX = "::ffff:"

# Only beacons at/above this RITA score become events; below it the
# regularity is too weak to be worth an analyst's attention.
DEFAULT_SCORE_THRESHOLD = 0.7


@dataclass(frozen=True)
class BeaconDetection:
    """A beacon worth surfacing, ready to serialize into ml_beacons."""

    src_ip: str
    dst_ip: str
    beacon_score: float
    connection_count: int
    confidence: int
    severity: str
    beacon_type: str = ""
    dst_domain: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)


def normalize_ip(addr: str) -> str:
    """Strip RITA's IPv4-mapped IPv6 prefix so IPs match the rest of the
    pipeline (Zeek/Suricata log plain IPv4)."""
    if addr.startswith(_V4_MAPPED_PREFIX):
        return addr[len(_V4_MAPPED_PREFIX) :]
    return addr


def score_to_confidence(score: float) -> int:
    """Map a RITA beacon score (0..1) to a 0..100 confidence.

    Composite-confidence (step 116) combines this with other signals, so a
    lone beacon is deliberately capped below the auto-enforce threshold
    (80): even a perfect 1.0 beacon yields 75, keeping single-signal
    beacons in the human-approval lane.
    """
    if score < 0:
        score = 0.0
    elif score > 1:
        score = 1.0
    return round(score * 75)


def score_to_severity(score: float) -> str:
    """Bucket a beacon score into the shared severity vocabulary."""
    if score >= 0.9:
        return "high"
    if score >= 0.8:
        return "medium"
    return "low"


@dataclass(frozen=True)
class BeaconRow:
    """One ``threat_mixtape`` row relevant to beaconing."""

    src: str
    dst: str
    beacon_score: float
    connection_count: int
    beacon_type: str = ""
    fqdn: str = ""


def build_detection(row: BeaconRow) -> BeaconDetection:
    """Turn a raw RITA row into a normalized BeaconDetection."""
    tags = ["beacon", "rita"]
    if row.beacon_type:
        tags.append(f"beacon:{row.beacon_type}")
    return BeaconDetection(
        src_ip=normalize_ip(row.src),
        dst_ip=normalize_ip(row.dst),
        beacon_score=round(row.beacon_score, 4),
        connection_count=row.connection_count,
        confidence=score_to_confidence(row.beacon_score),
        severity=score_to_severity(row.beacon_score),
        beacon_type=row.beacon_type,
        dst_domain=row.fqdn,
        tags=tuple(tags),
    )


def select_beacons(
    rows: list[BeaconRow], threshold: float = DEFAULT_SCORE_THRESHOLD
) -> list[BeaconDetection]:
    """Filter to at-or-above-threshold beacons and keep the highest score
    per source→destination pair (RITA can emit rolling duplicates)."""
    best: dict[tuple[str, str], BeaconDetection] = {}
    for row in rows:
        if row.beacon_score < threshold:
            continue
        det = build_detection(row)
        key = (det.src_ip, det.dst_ip)
        current = best.get(key)
        if current is None or det.beacon_score > current.beacon_score:
            best[key] = det
    return sorted(
        best.values(), key=lambda d: d.beacon_score, reverse=True
    )
