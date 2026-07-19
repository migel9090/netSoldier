# ADR-0003: First-party JA4 implementation, FoxIO-licensed JA4+ removed

- **Date:** 2026-07-19
- **Status:** Accepted
- **Deciders:** magiccactus42 (project owner), migel9090 (DevOps)
- **Amends:** ADR-0002 (the FoxIO package decision)

## Context and problem

ADR-0002 shipped TLS/HTTP fingerprinting via the `FoxIO-LLC/ja4` Zeek
package. Only the JA4 TLS client fingerprint is BSD-3-Clause; the rest of
the package's output (JA4S on ssl.log, JA4H on http.log, plus the
enabled-by-default JA4L/JA4SSH/JA4T/JA4D streams) is FoxIO License 1.1 and
patent-pending — **not monetizable without a FoxIO OEM license**. The owner
wants the option to commercialize netSoldier kept open at all times, which
makes any FoxIO-licensed component a standing liability. Reimplementing
JA4S/JA4H independently would not help: the FoxIO license and patent
applications cover the methods, not just the code.

## Decision

- Replace the `FoxIO-LLC/ja4` package with a **first-party, clean-room
  implementation of JA4 (TLS client)** — `deploy/docker/zeek/scripts/
  netsoldier-ja4.zeek` — written from the published specification, which is
  BSD-3-Clause. The spec being BSD is also why Wireshark and Suricata ship
  JA4 (and only JA4) natively. The script contains no FoxIO code.
- **Drop JA4S and JA4H** (and the incidental JA4L/JA4SSH/JA4T/JA4D
  streams). JA3S (BSD, salesforce/ja3) remains the server-side fingerprint;
  `zeek_ssl.ja4s` and `zeek_http.ja4h` are dropped by ClickHouse migration
  `012_drop_foxio_fingerprints.sql`.
- Keep `salesforce/ja3` (BSD-3-Clause) unchanged.
- Guard correctness with a **golden test** (`deploy/docker/zeek/test/`):
  9 ClientHellos — 6 captured live (TLS 1.2/1.3, with/without SNI/ALPN) and
  3 synthesized (GREASE ciphers/extensions/versions, GREASE first-ALPN hex
  rule) — must produce JA4 values byte-identical to Wireshark's independent
  implementation (`tshark -e tls.handshake.ja4`). The test runs in CI
  against the freshly built image before it is signed.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep FoxIO package, buy OEM license if ever needed | Leaves a standing encumbrance and a negotiation dependency on a third party; owner asked for the option to be unconditional. |
| Clean-room reimplementation of JA4S/JA4H too | License 1.1 and pending patents cover the methods; a reimplementation stays encumbered. |
| Drop the JA4 family entirely (JA3-only) | Loses the modern low-collision client fingerprint that threat-intel feeds increasingly key on; JA4 itself is BSD, so there is no reason to lose it. |
| Adopt another third-party JA4 Zeek package | None exists with BSD-only scope + our supply-chain pinning; a ~250-line first-party script is smaller than the audit surface of a dependency. |

## Consequences

- **Positive:** No FoxIO License 1.1 code or output anywhere in the stack —
  netSoldier is now fully monetizable without third-party fingerprinting
  licenses (GPL-3.0 own code, BSD dependencies). The sensor keeps `ja3`,
  `ja3s`, `ja4` on ssl.log; detection-engine IoC matching (`ja3`, `ja4`
  types) is unaffected. The fingerprint surface is smaller and fully
  understood; correctness is pinned by a CI golden test against an
  independent implementation.
- **Negative / accepted trade-offs:**
  - JA4S/JA4H columns (and any historical values) are gone; server-side
    fingerprinting falls back to JA3S, HTTP client fingerprinting is
    dropped until an unencumbered equivalent is designed.
  - QUIC ("q") and DTLS ("d") JA4 paths are implemented per spec but the
    golden corpus currently covers TCP TLS only; extend the corpus when
    QUIC traffic reaches the sensor (roadmap step 123 corpus expansion).
- **Follow-ups:** feed `ja4` into the Zeek Intel framework in step 107;
  consider a first-party HTTP client fingerprint with an original format if
  detection gaps appear (step 127+ heuristics territory).

## Links

- ADR-0002 (superseded FoxIO decision), roadmap step 106.
- `deploy/docker/zeek/scripts/netsoldier-ja4.zeek`,
  `deploy/docker/zeek/test/`, `/NOTICE`,
  ClickHouse migration `012_drop_foxio_fingerprints.sql`.
- JA4 spec (BSD-3-Clause): https://github.com/FoxIO-LLC/ja4 — independent
  implementations: Wireshark ≥4.2 (`tls.handshake.ja4`), Suricata ≥7.0.3.
