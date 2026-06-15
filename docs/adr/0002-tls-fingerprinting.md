# ADR-0002: Passive TLS/HTTP fingerprinting with JA3 + JA4+

- **Date:** 2026-06-12
- **Status:** Accepted
- **Deciders:** magiccactus42 (project owner), migel9090 (DevOps)

## Context and problem

Roadmap step 106 calls for "JA4/JA4+ (and JA3) + JARM" on the Zeek sensor,
exported to ClickHouse. Three forces constrain how we implement it:

1. **Architecture.** netSoldier is a *passive* monitor (SPAN tap,
   metadata-only, privacy-reviewed). JA3/JA4 are computed passively from
   TLS/HTTP handshakes already on the wire. **JARM is not passive** — it
   actively sends 10 crafted TLS Client Hellos to remote servers and hashes
   the responses. It has no passive form.
2. **Licensing.** Per the
   [FoxIO Licensing FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md):
   JA4 (TLS client) is **BSD-3-Clause**; the rest of JA4+ (JA4S, JA4H, JA4X,
   JA4L, JA4SSH, …) is **FoxIO License 1.1** — permissive for internal and
   defensive use, **not for monetization** without a FoxIO OEM license.
   JA3/JA3S (salesforce/ja3) are BSD-3-Clause. netSoldier itself is GPL-3.0.
3. **Deployment.** JA4 is a third-party Zeek package; the stock `zeek/zeek`
   image does not ship it, and the runtime is `readOnlyRootFilesystem` with
   no build tools — packages cannot be installed at pod start.

## Decision

We will ship **passive** TLS/HTTP fingerprinting only:

- **salesforce/ja3** → `ja3`, `ja3s` on `ssl.log` (+ JA3 Intel entries, which
  feed IoC correlation via `threat-intel-sync` `TypeJA3`).
- **FoxIO-LLC/ja4 v0.18.8** → `ja4` on `ssl.log` (BSD), `ja4s` on `ssl.log`
  and `ja4h` on `http.log` (FoxIO License 1.1).

Both packages are pure Zeek script, baked into a **custom, cosign-signed
image** (`ghcr.io/migel9090/zeek`, amd64-only — Zeek runs on `proxmox-soc`
only) built, signed and SLSA-provenanced in CI like every first-party image.
The packages run inside the BSD-licensed Zeek process and are loaded via
`@load packages`; the GPL-3.0 Go services consume only the resulting
ClickHouse rows — an **arm's-length** separation per the FoxIO FAQ's
guidance on combining JA4+ with GPL software.

**We will NOT implement JARM.** It is active scanning and is removed from the
roadmap as out of scope for a passive monitor.

This ADR does **not** decide active fingerprinting (JARM and friends), nor
host-based fingerprinting; those remain out of scope unless separately
approved.

## Alternatives considered

| Option | Why not |
|---|---|
| Implement JARM as documented in step 106 | Active outbound scanning; breaks the passive/metadata-only architecture and privacy posture. Owner chose to drop it. |
| Install JA4 via `zkg` at pod start | Needs a writable FS + build tooling at runtime; conflicts with `readOnlyRootFilesystem`. A prebuilt image is the clean fit. |
| Reference an upstream prebuilt JA4 image | None exists with our pinned, signed supply-chain guarantees; Kyverno requires a cosign signature for `ghcr.io/migel9090/*`. |
| JA3 only (skip the FoxIO package) | Loses JA4/JA4S/JA4H, the modern fingerprints with far lower collision rates; owner accepted the FoxIO License with documentation. |
| Enable JA4X (cert fingerprint) too | Defaults off in the package and toggling it cleanly hits Zeek's `@if`/`option` parse-order; deferred to avoid an unverifiable change. |

## Consequences

- **Positive:** Modern, low-collision passive fingerprints across TLS and
  HTTP; JA3 stays for backward-compatible IoC feeds; the sensor image is
  pinned, signed and provenanced; the architecture stays strictly passive.
- **Negative / accepted trade-offs:**
  - **FoxIO License 1.1 (JA4+) is non-monetizable without an OEM license.**
    The README advertises "free for commercial use" — that holds for the
    GPL-3.0 code and for JA4/JA3, but **NOT for JA4S/JA4H**. If netSoldier is
    ever sold or offered as a paid service, obtain a FoxIO OEM license, or
    rebuild the image without `FoxIO-LLC/ja4` (keeping `salesforce/ja3` for
    JA3/JA3S; both BSD), accepting loss of the JA4 family.
  - The FoxIO package also enables JA4L/JA4SSH/JA4T/JA4D at their defaults;
    those extra `fingerprint_*.log` streams are written but not ingested
    (rotated + deleted on the 30-min cycle). Trim at the cost/perf step.
  - The custom image build runs `zkg install` of external packages; pinned
    by tag (`v0.18.8`) and commit, built in the sandboxed, egress-audited CI
    runner — first verification of the build is in CI, not locally.
- **Follow-ups:** optionally enable JA4X (step into x509.log) once the
  `@if`/option ordering is verified; revisit the JA4+ sub-fingerprint set at
  the cost/perf tuning step (162); resolve the OEM-license question before
  any commercial offering.

## Links

- ADR-0001 (architecture), roadmap steps 105 (Zeek deploy) and 106 (this).
- `/NOTICE`, `deploy/docker/zeek/Dockerfile`, `deploy/kustomize/base/zeek/`.
- FoxIO JA4: https://github.com/FoxIO-LLC/ja4 — Salesforce JA3:
  https://github.com/salesforce/ja3
