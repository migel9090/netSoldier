#!/usr/bin/env python3
"""Synthesize a pcap with hand-crafted TLS ClientHellos exercising TLS client fingerprint (JA4-format) edge
cases OpenSSL clients never produce: GREASE ciphers/extensions/versions and a
GREASE (non-alphanumeric) first ALPN value.

Each flow: TCP handshake + one ClientHello + RST. Checksums: IP valid, TCP
zeroed (zeek runs with -C, tshark dissects regardless).
"""
import struct

def ip_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) | hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def eth(payload: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + payload

def ipv4(src: bytes, dst: bytes, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0x1234, 0x4000, 64, 6, 0, src, dst)
    ck = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack(">H", ck) + hdr[12:]
    return hdr + payload

def tcp(sport, dport, seq, ack, flags, payload=b"") -> bytes:
    offs = 5 << 12
    return struct.pack(">HHIIHHHH", sport, dport, seq, ack, offs | flags, 65535, 0, 0) + payload

IP_C = bytes([10, 99, 0, 1])
IP_S = bytes([10, 99, 0, 2])

def flow(sport, hello: bytes):
    pkts = []
    cseq, sseq = 1000, 2000
    pkts.append(eth(ipv4(IP_C, IP_S, tcp(sport, 443, cseq, 0, 0x02))))            # SYN
    pkts.append(eth(ipv4(IP_S, IP_C, tcp(443, sport, sseq, cseq + 1, 0x12))))     # SYN-ACK
    pkts.append(eth(ipv4(IP_C, IP_S, tcp(sport, 443, cseq + 1, sseq + 1, 0x10)))) # ACK
    pkts.append(eth(ipv4(IP_C, IP_S, tcp(sport, 443, cseq + 1, sseq + 1, 0x18, hello))))
    pkts.append(eth(ipv4(IP_S, IP_C, tcp(443, sport, sseq + 1, cseq + 1 + len(hello), 0x10))))
    pkts.append(eth(ipv4(IP_C, IP_S, tcp(sport, 443, cseq + 1 + len(hello), sseq + 1, 0x04))))  # RST
    return pkts

def ext(code: int, body: bytes) -> bytes:
    return struct.pack(">HH", code, len(body)) + body

def sni(name: bytes) -> bytes:
    entry = b"\x00" + struct.pack(">H", len(name)) + name
    return ext(0x0000, struct.pack(">H", len(entry)) + entry)

def alpn(protos) -> bytes:
    lst = b"".join(bytes([len(p)]) + p for p in protos)
    return ext(0x0010, struct.pack(">H", len(lst)) + lst)

def u16list_ext(code: int, vals) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in vals)
    return ext(code, struct.pack(">H", len(body)) + body)

def supported_versions(vals) -> bytes:
    body = b"".join(struct.pack(">H", v) for v in vals)
    return ext(0x002B, bytes([len(body)]) + body)

def client_hello(ciphers, extensions: bytes) -> bytes:
    body = struct.pack(">H", 0x0303) + bytes(range(32)) + b"\x00"
    body += struct.pack(">H", 2 * len(ciphers)) + b"".join(struct.pack(">H", c) for c in ciphers)
    body += b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

# Flow 1: GREASE everywhere + SNI + ALPN h2 + sigalgs + supported_versions
exts1 = (
    ext(0x1A1A, b"")                                   # GREASE extension
    + sni(b"synthetic.test")
    + u16list_ext(0x000A, [0x2A2A, 0x001D, 0x0017])    # groups w/ GREASE
    + alpn([b"h2", b"http/1.1"])
    + u16list_ext(0x000D, [0x0403, 0x0804, 0x0401])    # signature_algorithms
    + supported_versions([0x0A0A, 0x0304, 0x0303])
)
hello1 = client_hello([0x8A8A, 0x1301, 0x1302, 0xC02B, 0xC02F], exts1)

# Flow 2: no SNI, no ALPN, no sigalgs, no supported_versions (TLS 1.2 legacy)
exts2 = u16list_ext(0x000A, [0x001D, 0x0017]) + ext(0x0023, b"")
hello2 = client_hello([0xC02B, 0xC02F, 0x009C], exts2)

# Flow 3: GREASE first ALPN value (non-alphanumeric -> hex rule)
exts3 = (
    sni(b"grease-alpn.test")
    + alpn([b"\x0A\x0A", b"h2"])
    + u16list_ext(0x000D, [0x0403])
    + supported_versions([0x0304])
)
hello3 = client_hello([0x1301, 0x1303], exts3)

with open("synthetic.pcap", "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    ts = 1700000000
    for i, h in enumerate([hello1, hello2, hello3]):
        for j, p in enumerate(flow(40000 + i, h)):
            f.write(struct.pack("<IIII", ts + i, j * 1000, len(p), len(p)))
            f.write(p)
print("synthetic.pcap written")
