#!/usr/bin/env python3
"""Generate the netSoldier PCAP corpus — one capture per malware/C2 traffic
family, for detection regression testing (Suricata + Zeek + detection-engine).

Why generated rather than captured: the corpus must be replayable in CI on
every PR, which rules out anything that has to be downloaded from a third
party at test time. Real-world captures (malware-traffic-analysis.net) are
referenced from manifest.yaml as pinned, optional entries for deep local
validation — see README.md.

Everything here is deterministic: fixed timestamps, no RNG (per-family
variation is derived from SHA-256 of a label), so re-running produces
byte-identical files and the sha256 pins in manifest.yaml stay valid.

Addressing uses only documentation ranges (RFC 5737: 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and reserved domains (RFC 2606 .example /
example.com), so nothing here can be confused with a real host or C2.

Usage: ./gen_corpus.py [output-dir]   (default: ./pcaps)
"""

import hashlib
import os
import struct
import sys

# ── Deterministic pseudo-randomness ─────────────────────────────────────


def det(tag: str, n: int) -> bytes:
    """n bytes derived from tag — stable across Python versions, unlike random."""
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{tag}:{i}".encode()).digest()
        i += 1
    return out[:n]


# ── Layer 2/3/4 ─────────────────────────────────────────────────────────

MAC_CLIENT = b"\x02\x00\x00\x00\x00\x01"
MAC_GW = b"\x02\x00\x00\x00\x00\xfe"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(src: bytes, dst: bytes, payload: bytes) -> bytes:
    return dst + src + b"\x08\x00" + payload


def ip4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    hdr = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0, s, d
    )
    hdr = hdr[:10] + struct.pack(">H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def l4_checksum(src: str, dst: str, proto: int, seg: bytes) -> int:
    s = bytes(int(x) for x in src.split("."))
    d = bytes(int(x) for x in dst.split("."))
    pseudo = s + d + struct.pack(">BBH", 0, proto, len(seg))
    return checksum(pseudo + seg)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ck = l4_checksum(src, dst, 17, seg) or 0xFFFF
    return seg[:6] + struct.pack(">H", ck) + seg[8:]


# TCP flags
SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


def tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    ck = l4_checksum(src, dst, 6, seg)
    return seg[:16] + struct.pack(">H", ck) + seg[18:]


class Capture:
    """Accumulates timestamped frames and writes a libpcap file."""

    def __init__(self):
        self.packets = []  # (ts_float, frame_bytes)

    def add(self, ts: float, frame: bytes):
        self.packets.append((ts, frame))

    def write(self, path: str):
        with open(path, "wb") as f:
            # magic, major, minor, thiszone, sigfigs, snaplen, LINKTYPE_ETHERNET
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, pkt in self.packets:
                f.write(struct.pack("<IIII", int(ts), round((ts % 1) * 1e6), len(pkt), len(pkt)))
                f.write(pkt)
        return len(self.packets)


class TCPFlow:
    """Tracks sequence state so crafted flows reassemble in Zeek/Suricata."""

    def __init__(self, cap: Capture, cip: str, sip: str, sport: int, dport: int, tag: str):
        self.cap, self.cip, self.sip = cap, cip, sip
        self.sport, self.dport = sport, dport
        self.cseq = 1 + int.from_bytes(det(f"cseq:{tag}", 3), "big")
        self.sseq = 1 + int.from_bytes(det(f"sseq:{tag}", 3), "big")
        self.ident = 0x1000

    def _c2s(self, ts, flags, payload=b""):
        self.ident += 1
        seg = tcp(
            self.cip,
            self.sip,
            self.sport,
            self.dport,
            self.cseq,
            self.sseq if flags & ACK else 0,
            flags,
            payload,
        )
        self.cap.add(ts, eth(MAC_CLIENT, MAC_GW, ip4(self.cip, self.sip, 6, seg, self.ident)))
        self.cseq += len(payload) + (1 if flags & (SYN | FIN) else 0)

    def _s2c(self, ts, flags, payload=b""):
        self.ident += 1
        seg = tcp(self.sip, self.cip, self.dport, self.sport, self.sseq, self.cseq, flags, payload)
        self.cap.add(ts, eth(MAC_GW, MAC_CLIENT, ip4(self.sip, self.cip, 6, seg, self.ident)))
        self.sseq += len(payload) + (1 if flags & (SYN | FIN) else 0)

    def handshake(self, ts):
        self._c2s(ts, SYN)
        self._s2c(ts + 0.012, SYN | ACK)
        self._c2s(ts + 0.024, ACK)

    def request(self, ts, payload):
        self._c2s(ts, PSH | ACK, payload)
        self._s2c(ts + 0.008, ACK)

    def response(self, ts, payload):
        self._s2c(ts, PSH | ACK, payload)
        self._c2s(ts + 0.008, ACK)

    def close(self, ts):
        self._c2s(ts, FIN | ACK)
        self._s2c(ts + 0.010, FIN | ACK)
        self._c2s(ts + 0.020, ACK)


# ── DNS ─────────────────────────────────────────────────────────────────


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    return (
        struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + dns_name(qname)
        + struct.pack(">HH", qtype, 1)
    )


def dns_response(txid: int, qname: str, qtype: int, rdata: bytes | None, rcode: int = 0) -> bytes:
    ancount = 1 if rdata else 0
    msg = (
        struct.pack(">HHHHHH", txid, 0x8180 | rcode, 1, ancount, 0, 0)
        + dns_name(qname)
        + struct.pack(">HH", qtype, 1)
    )
    if rdata:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(rdata)) + rdata
    return msg


def a_record(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def txt_record(text: bytes) -> bytes:
    return bytes([len(text)]) + text


def dns_exchange(
    cap: Capture,
    ts: float,
    client: str,
    resolver: str,
    txid: int,
    qname: str,
    qtype: int = 1,
    rdata: bytes | None = None,
    rcode: int = 0,
):
    sport = 40000 + (txid % 20000)
    q = udp(client, resolver, sport, 53, dns_query(txid, qname, qtype))
    cap.add(ts, eth(MAC_CLIENT, MAC_GW, ip4(client, resolver, 17, q, txid)))
    r = udp(resolver, client, 53, sport, dns_response(txid, qname, qtype, rdata, rcode))
    cap.add(ts + 0.004, eth(MAC_GW, MAC_CLIENT, ip4(resolver, client, 17, r, txid)))


# ── TLS ClientHello ─────────────────────────────────────────────────────


def _ext(code: int, body: bytes) -> bytes:
    return struct.pack(">HH", code, len(body)) + body


def _sni_ext(host: str) -> bytes:
    entry = b"\x00" + struct.pack(">H", len(host)) + host.encode()
    return _ext(0x0000, struct.pack(">H", len(entry)) + entry)


def _u16list(code: int, vals) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in vals)
    return _ext(code, struct.pack(">H", len(body)) + body)


def _alpn(protos) -> bytes:
    lst = b"".join(bytes([len(p)]) + p for p in protos)
    return _ext(0x0010, struct.pack(">H", len(lst)) + lst)


# TLS client profiles. Each yields a distinct tls_client_fp, which is the
# point: a fingerprint IoC must be able to single out the implant without
# catching the browser, and the corpus can only prove that if the captures
# genuinely differ. Values are pinned in manifest.yaml.
BROWSER = {
    "ciphers": [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C, 0x009D],
    "groups": [0x001D, 0x0017, 0x0018],
    "sigalgs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805],
    "alpn": [b"h2", b"http/1.1"],
    "versions": [0x0304, 0x0303],
}
IMPLANT = {  # small, dated cipher list — typical of a hand-rolled C2 client
    "ciphers": [0xC02F, 0xC030, 0x009C],
    "groups": [0x0017],
    "sigalgs": [0x0401],
    "alpn": [b"http/1.1"],
    "versions": [0x0303],
}


def client_hello(host: str | None, tag: str, profile=BROWSER) -> bytes:
    """A TLS ClientHello parsed by Zeek (ssl.log + tls_client_fp) and Suricata
    (tls.sni). host=None omits SNI entirely, as a direct-to-IP client does."""
    exts = b""
    if host is not None:
        exts += _sni_ext(host)
    exts += (
        _u16list(0x000A, profile["groups"])
        + _alpn(profile["alpn"])
        + _u16list(0x000D, profile["sigalgs"])
        + _ext(
            0x002B,
            bytes([2 * len(profile["versions"])])
            + b"".join(struct.pack(">H", v) for v in profile["versions"]),
        )
    )
    ciphers = profile["ciphers"]
    body = (
        struct.pack(">H", 0x0303)
        + det(f"random:{tag}", 32)
        + b"\x00"
        + struct.pack(">H", 2 * len(ciphers))
        + b"".join(struct.pack(">H", c) for c in ciphers)
        + b"\x01\x00"
        + struct.pack(">H", len(exts))
        + exts
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def server_hello_flight() -> bytes:
    """Minimal ServerHello + ChangeCipherSpec so the flow looks established.
    Zeek logs the connection either way; this keeps conn_state from being S1."""
    body = (
        struct.pack(">H", 0x0303)
        + det("server-random", 32)
        + b"\x00"
        + struct.pack(">H", 0x1301)
        + b"\x00"
        + struct.pack(">H", 6)
        + _ext(0x002B, struct.pack(">H", 0x0304))
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs + b"\x14\x03\x03\x00\x01\x01"


# ── Hosts ───────────────────────────────────────────────────────────────

RESOLVER = "192.168.1.1"
BASE_TS = 1768467600.0  # 2026-01-15 09:00:00 UTC — fixed for reproducibility


# ── Families ────────────────────────────────────────────────────────────


def gen_c2_http_beacon() -> Capture:
    """T1071.001 — fixed-interval HTTP callbacks to a C2 gate, the shape RITA
    scores as beaconing. 12 beacons, 60s apart, +/- 2s jitter."""
    cap, client, server = Capture(), "192.168.1.50", "203.0.113.10"
    host = "cdn.badupdate.example"
    dns_exchange(cap, BASE_TS, client, RESOLVER, 0x1001, host, 1, a_record(server))
    for i in range(12):
        jitter = (det(f"beacon-jitter:{i}", 1)[0] % 41 - 20) / 10.0
        ts = BASE_TS + 5 + i * 60 + jitter
        f = TCPFlow(cap, client, server, 49152 + i, 80, f"http-beacon:{i}")
        f.handshake(ts)
        body = det(f"beacon-id:{i}", 8).hex()
        req = (
            f"GET /api/v1/gate.php?id={body} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0)\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        ).encode()
        f.request(ts + 0.05, req)
        resp = (
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: 16\r\nConnection: close\r\n\r\n" + det(f"task:{i}", 16)
        )
        f.response(ts + 0.12, resp)
        f.close(ts + 0.2)
    return cap


def gen_c2_tls_beacon() -> Capture:
    """T1071.001/T1573 — HTTPS C2 check-ins. Detection is metadata-only:
    SNI plus the TLS client fingerprint, never payload."""
    cap, client, server = Capture(), "192.168.1.51", "203.0.113.20"
    host = "panel.evilcorp.example"
    dns_exchange(cap, BASE_TS, client, RESOLVER, 0x2001, host, 1, a_record(server))
    for i in range(10):
        ts = BASE_TS + 10 + i * 300
        f = TCPFlow(cap, client, server, 51000 + i, 443, f"tls-beacon:{i}")
        f.handshake(ts)
        f.request(ts + 0.03, client_hello(host, f"c2:{i}", IMPLANT))
        f.response(ts + 0.09, server_hello_flight())
        f.request(ts + 0.15, b"\x17\x03\x03" + struct.pack(">H", 48) + det(f"c2-app:{i}", 48))
        f.close(ts + 0.3)
    return cap


def gen_dns_dga() -> Capture:
    """T1568.002 — domain generation algorithm: a burst of high-entropy
    labels, nearly all NXDOMAIN, then one that resolves (the live rendezvous)."""
    cap, client = Capture(), "192.168.1.52"
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for i in range(20):
        raw = det(f"dga:{i}", 16)
        label = "".join(alphabet[b % 26] for b in raw[: 12 + raw[12] % 4])
        resolves = i == 17
        dns_exchange(
            cap,
            BASE_TS + i * 1.5,
            client,
            RESOLVER,
            0x3000 + i,
            f"{label}.example",
            1,
            a_record("203.0.113.30") if resolves else None,
            0 if resolves else 3,
        )  # 3 = NXDOMAIN
    return cap


def gen_dns_tunnel_exfil() -> Capture:
    """T1048.003/T1071.004 — data exfiltrated through DNS: long encoded
    labels under one delegated zone, TXT answers carrying the reply channel."""
    cap, client = Capture(), "192.168.1.53"
    zone = "t.exfil-tunnel.example"
    for i in range(15):
        chunk = det(f"exfil:{i}", 30).hex()[:48]  # 48-char label, base16-ish
        qname = f"{chunk}.{zone}"
        dns_exchange(
            cap,
            BASE_TS + i * 0.8,
            client,
            RESOLVER,
            0x4000 + i,
            qname,
            16,
            txt_record(det(f"exfil-reply:{i}", 24).hex().encode()),
        )
    return cap


def gen_scan_portsweep() -> Capture:
    """T1046 — internal port sweep: SYNs with no reply, which Zeek records as
    S0 connections. The lateral-movement heuristics key off this fan-out."""
    cap, scanner = Capture(), "192.168.1.77"
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        443,
        445,
        1433,
        3306,
        3389,
        5432,
        5900,
        8080,
        8443,
    ]
    ts = BASE_TS
    ident = 0
    for target in ("192.168.1.10", "192.168.1.11", "192.168.1.12"):
        for p in ports:
            ident += 1
            seg = tcp(scanner, target, 44000 + ident, p, 1000 + ident, 0, SYN)
            cap.add(ts, eth(MAC_CLIENT, MAC_GW, ip4(scanner, target, 6, seg, ident)))
            ts += 0.02
        ts += 0.5
    return cap


def gen_ioc_ip_contact() -> Capture:
    """T1571 — direct-to-IP connection on a non-standard port, no DNS lookup
    first (matches the IoC-IP dataset rule and the dns-less-TLS heuristic)."""
    cap, client, server = Capture(), "192.168.1.55", "198.51.100.66"
    for i in range(3):
        ts = BASE_TS + i * 45
        f = TCPFlow(cap, client, server, 52000 + i, 8443, f"ioc-ip:{i}")
        f.handshake(ts)
        # No SNI at all — the client already knows the address, so there is
        # nothing to resolve and nothing to name.
        f.request(ts + 0.04, client_hello(None, f"ioc-ip:{i}", IMPLANT))
        f.response(ts + 0.10, server_hello_flight())
        f.close(ts + 0.25)
    return cap


def gen_benign_baseline() -> Capture:
    """False-positive guard: ordinary browsing that must produce zero IoC
    alerts. A corpus that only contains malicious traffic cannot catch a rule
    that alerts on everything."""
    cap, client = Capture(), "192.168.1.60"
    sites = [
        ("www.example.com", "93.184.216.34"),
        ("api.example.org", "203.0.113.80"),
        ("cdn.example.net", "203.0.113.81"),
    ]
    for i, (host, ip) in enumerate(sites):
        dns_exchange(cap, BASE_TS + i * 2, client, RESOLVER, 0x5000 + i, host, 1, a_record(ip))
    # one HTTPS session and one plain-HTTP fetch
    f = TCPFlow(cap, client, sites[0][1], 53000, 443, "benign-tls")
    f.handshake(BASE_TS + 10)
    f.request(BASE_TS + 10.05, client_hello(sites[0][0], "benign"))
    f.response(BASE_TS + 10.11, server_hello_flight())
    f.close(BASE_TS + 10.4)
    g = TCPFlow(cap, client, sites[1][1], 53001, 80, "benign-http")
    g.handshake(BASE_TS + 20)
    g.request(
        BASE_TS + 20.05,
        f"GET /v2/status HTTP/1.1\r\nHost: {sites[1][0]}\r\n"
        "User-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n".encode(),
    )
    g.response(
        BASE_TS + 20.12,
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        b'Content-Length: 15\r\n\r\n{"status":"ok"}',
    )
    g.close(BASE_TS + 20.3)
    return cap


FAMILIES = {
    "c2-http-beacon": gen_c2_http_beacon,
    "c2-tls-beacon": gen_c2_tls_beacon,
    "dns-dga": gen_dns_dga,
    "dns-tunnel-exfil": gen_dns_tunnel_exfil,
    "scan-portsweep": gen_scan_portsweep,
    "ioc-ip-contact": gen_ioc_ip_contact,
    "benign-baseline": gen_benign_baseline,
}


def main():
    out = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcaps")
    )
    os.makedirs(out, exist_ok=True)

    print(f"{'family':<20} {'packets':>7}  sha256")
    for name, fn in FAMILIES.items():
        path = os.path.join(out, f"{name}.pcap")
        count = fn().write(path)
        with open(path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        print(f"{name:<20} {count:>7}  {digest}")


if __name__ == "__main__":
    main()
