"""RITA beaconing → netSoldier detection rows (roadmap steps 112, 125.23).

RITA imports Zeek conn logs and scores each internal→external pair for
beaconing regularity in ``<db>.threat_mixtape``. This module turns
high-scoring beacons into ``ml_beacons`` rows with a calibrated confidence.

A beacon is identified by (source, destination, name): RITA stores TLS SNI
beacons with the unspecified address as ``dst`` and the server name in
``fqdn``, so a key on (source, destination) alone would collapse every SNI
beacon of a device into one.

The table is append-only and RITA re-reports every pair on each import, so
the sync keeps emission state (:class:`EmissionState`) and only emits a
beacon when it is new or has materially changed (score up by at least
``rescore_delta`` since the last emission, or a higher severity bucket).
Each row carries RITA's ``last_seen`` as its observation time.

The mapping and emission logic here are pure and unit-tested; the ClickHouse
I/O lives in :mod:`ml_anomaly.clickhouse`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

# RITA stores addresses as IPv4-mapped IPv6 ("::ffff:192.168.1.50").
_V4_MAPPED_PREFIX = "::ffff:"

# Only beacons at/above this RITA score become events; below it the
# regularity is too weak to be worth an analyst's attention.
DEFAULT_SCORE_THRESHOLD = 0.7

# Re-emit an already-reported beacon when its score has risen by this much.
DEFAULT_RESCORE_DELTA = 0.1

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
_UINT32_MAX = 2**32 - 1


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
    last_seen: int = 0  # RITA's last_seen (unix seconds): the observation time

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.src_ip, self.dst_ip, self.dst_domain)


def normalize_ip(addr: str) -> str:
    """Canonical text form, without RITA's IPv4-mapped prefix, so addresses
    match the rest of the pipeline (Zeek/Suricata log plain IPv4).

    The unspecified address (RITA's ``dst`` for SNI beacons) becomes "": it
    is not a destination, and an IP target of "::" must never reach the
    enforcement path.
    """
    addr = addr.strip()
    if addr.startswith(_V4_MAPPED_PREFIX):
        addr = addr[len(_V4_MAPPED_PREFIX) :]
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return addr
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return ""
    return str(ip)


def normalize_name(name: str) -> str:
    """Server names are case-insensitive; a trailing dot is the same name."""
    return name.strip().rstrip(".").lower()


def score_to_confidence(score: float) -> int:
    """Map a RITA beacon score (0..1) to a 0..100 confidence.

    Composite-confidence (step 116) combines this with other signals, so a
    lone beacon is deliberately capped below the auto-enforce threshold
    (80): even a perfect 1.0 beacon yields 75, keeping single-signal
    beacons in the human-approval lane.
    """
    if not score >= 0:  # also catches NaN
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
    """The newest ``threat_mixtape`` observation of one pair."""

    src: str
    dst: str
    beacon_score: float
    connection_count: int
    beacon_type: str = ""
    fqdn: str = ""
    last_seen: int = 0


@dataclass(frozen=True)
class EmittedBeacon:
    """A row this worker already wrote to ``ml_beacons``."""

    src_ip: str
    dst_ip: str
    dst_domain: str
    beacon_score: float
    severity: str
    last_seen: int


def build_detection(row: BeaconRow) -> BeaconDetection:
    """Turn a raw RITA row into a normalized BeaconDetection."""
    tags = ["beacon", "rita"]
    if row.beacon_type:
        tags.append(f"beacon:{row.beacon_type}")
    return BeaconDetection(
        src_ip=normalize_ip(row.src),
        dst_ip=normalize_ip(row.dst),
        beacon_score=round(row.beacon_score, 4),
        connection_count=max(0, min(row.connection_count, _UINT32_MAX)),
        confidence=score_to_confidence(row.beacon_score),
        severity=score_to_severity(row.beacon_score),
        beacon_type=row.beacon_type,
        dst_domain=normalize_name(row.fqdn),
        tags=tuple(tags),
        last_seen=row.last_seen,
    )


def select_beacons(
    rows: list[BeaconRow], threshold: float = DEFAULT_SCORE_THRESHOLD
) -> list[BeaconDetection]:
    """Filter to at-or-above-threshold beacons and keep one per
    (source, destination, name): the newest observation, then the higher
    score."""
    best: dict[tuple[str, str, str], BeaconDetection] = {}
    for row in rows:
        if not row.beacon_score >= threshold:
            continue
        det = build_detection(row)
        if not det.src_ip or not (det.dst_ip or det.dst_domain):
            continue
        current = best.get(det.key)
        if current is None or (det.last_seen, det.beacon_score) > (
            current.last_seen,
            current.beacon_score,
        ):
            best[det.key] = det
    return sorted(best.values(), key=lambda d: (-d.beacon_score, d.key))


@dataclass
class Tracked:
    """What was last emitted for a beacon, and when it was last observed."""

    score: float  # beacon_score of the last emission
    severity: str  # severity of the last emission
    emitted_seen: int  # last_seen carried by the last emission
    last_seen: int  # newest last_seen observed (emitted or not)


class EmissionState:
    """Per-beacon emission memory; serialisable so it survives restarts."""

    VERSION = 1

    def __init__(self, entries: dict[tuple[str, str, str], Tracked] | None = None) -> None:
        self.entries: dict[tuple[str, str, str], Tracked] = entries or {}

    def to_json(self) -> dict:
        return {
            "version": self.VERSION,
            "beacons": [
                {
                    "src_ip": k[0],
                    "dst_ip": k[1],
                    "dst_domain": k[2],
                    "score": t.score,
                    "severity": t.severity,
                    "emitted_seen": t.emitted_seen,
                    "last_seen": t.last_seen,
                }
                for k, t in sorted(self.entries.items())
            ],
        }

    @classmethod
    def from_json(cls, raw: object) -> EmissionState:
        if not isinstance(raw, dict) or raw.get("version") != cls.VERSION:
            raise ValueError("unsupported beacon state format")
        entries: dict[tuple[str, str, str], Tracked] = {}
        for e in raw.get("beacons", []):
            key = (str(e["src_ip"]), str(e["dst_ip"]), str(e["dst_domain"]))
            entries[key] = Tracked(
                score=float(e["score"]),
                severity=str(e["severity"]),
                emitted_seen=int(e["emitted_seen"]),
                last_seen=int(e["last_seen"]),
            )
        return cls(entries)

    def absorb_emitted(self, rows: list[EmittedBeacon]) -> int:
        """Adopt emissions found in ``ml_beacons`` that this state does not
        know about yet (lost state file, or a crash between the insert and
        the state write). Returns how many entries changed."""
        changed = 0
        for r in rows:
            key = (
                normalize_ip(r.src_ip),
                normalize_ip(r.dst_ip),
                normalize_name(r.dst_domain),
            )
            cur = self.entries.get(key)
            if cur is None or r.last_seen > cur.emitted_seen:
                self.entries[key] = Tracked(
                    score=r.beacon_score,
                    severity=r.severity,
                    emitted_seen=r.last_seen,
                    last_seen=max(r.last_seen, cur.last_seen if cur else 0),
                )
                changed += 1
        return changed

    def plan(
        self,
        detections: list[BeaconDetection],
        forget_before: int,
        rescore_delta: float = DEFAULT_RESCORE_DELTA,
    ) -> list[tuple[BeaconDetection, str]]:
        """Decide what to emit and update the state as if it was emitted.

        Returns (detection, reason) pairs with reason ``new`` or
        ``changed``. Beacons not observed since ``forget_before`` are
        dropped from the state, so one that returns later counts as new.
        """
        out: list[tuple[BeaconDetection, str]] = []
        for det in detections:
            cur = self.entries.get(det.key)
            if cur is None:
                reason = "new"
            elif det.last_seen < cur.last_seen:
                continue  # an older observation than one already handled
            elif det.beacon_score >= cur.score + rescore_delta or _SEVERITY_RANK.get(
                det.severity, 0
            ) > _SEVERITY_RANK.get(cur.severity, 0):
                reason = "changed"
            else:
                cur.last_seen = max(cur.last_seen, det.last_seen)
                continue
            self.entries[det.key] = Tracked(
                score=det.beacon_score,
                severity=det.severity,
                emitted_seen=det.last_seen,
                last_seen=max(det.last_seen, cur.last_seen if cur else 0),
            )
            out.append((det, reason))
        for key in [k for k, t in self.entries.items() if t.last_seen < forget_before]:
            del self.entries[key]
        return out
