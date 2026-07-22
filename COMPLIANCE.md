# netSoldier — Licensing & Monetization Compliance

netSoldier is **GPL-3.0**. This document records the licensing posture of every
third-party component and data feed, so the project can be run commercially
without hitting a non-commercial or proprietary restriction. Audit date:
**2026-07-19**.

**Rule of thumb:** copyleft (GPL / AGPL / LGPL / MPL) and permissive
(BSD / MIT / Apache) are all fine for monetization — copyleft only obliges you
to offer source. The things that block commercialization are **non-commercial
clauses**, **source-available-but-not-OSS** licenses, **proprietary data**, and
**trademark misuse**. Those are called out below and each is neutralized in the
codebase.

## Verdict

The **default build is monetization-safe.** Every bundled software component is
copyleft or permissive. The data sources whose terms forbid free commercial use
are either removed, replaced with first-party data, or gated behind
`COMMERCIAL_MODE` (see below). The only standing obligations are attribution and
trademark-naming caution.

## `COMMERCIAL_MODE`

`threat-intel-sync` reads a `COMMERCIAL_MODE` env var (`true`/`1`/`yes`). It
defaults to **off**, because the project's primary use is a private home
network monitor, where the non-commercial feeds are permitted. Set it to
**`true`** for any commercial deployment: the abuse.ch feeds (ThreatFox /
URLhaus / Feodo) are then not registered as sources, and only
commercial-safe intel remains (your own MISP + Spamhaus DROP).

## How each monetization blocker is handled here

| Blocker (audit) | Restriction | Handling in this repo |
|---|---|---|
| **FoxIO JA4+** (JA4S/H/L/X/SSH/T/D) | FoxIO License 1.1 — non-commercial | **Removed.** Only the JA4 TLS-client fingerprint (BSD spec) is implemented, clean-room, as `tls_client_fp`. ADR-0003. |
| **"JA4" trademark** | FoxIO common-law mark | **Not used as our name.** Field/type/branding is `tls_client_fp` / `tlsfp` / `Intel::TLSFP`; "JA4" appears only nominatively ("JA4-format"). |
| **GreyNoise Community API** | Free tier EULA — non-commercial / internal only | **Removed** (was unwired). Re-add only under a paid GreyNoise agreement. |
| **abuse.ch ThreatFox / URLhaus / Feodo** | CC0 dedication removed 2025; free tier now non-commercial | **Gated behind `COMMERCIAL_MODE`** (off by default = enabled for home use). |
| **Fingerbank device DB / API** | Proprietary (no redistribution grant) | **Never used.** Device profiling is a first-party table (`internal/dhcpfp`), our own data — not Fingerbank's. |

## Full component license table

| Component | License | Commercial | Notes / obligation |
|---|---|---|---|
| Zeek | BSD-3 | ✅ | Don't call a *modified* build "Zeek". |
| salesforce/ja3 | BSD-3 | ✅ | — |
| JA4 fingerprint **spec** | BSD-3 (`LICENSE-JA4`) | ✅ | Clean-room impl only; JA4+ is a separate, non-commercial license (excluded). |
| ntopng Community Edition | GPL-3.0 | ✅ | CE cannot export flows to ClickHouse (Enterprise-only) — used as live nDPI UI only. |
| nDPI | LGPL-3.0 | ✅ | — |
| DB-IP Lite (bundled in ntopng) | CC-BY-4.0 | ✅ | **Attribution required** in the UI ("IP Geolocation by DB-IP"). |
| DB-IP Lite mmdb (Vector geo/ASN enrichment, step 120) | CC-BY-4.0 | ✅ | Same **attribution** obligation — carried in the Grafana panel descriptions that show country/ASN data. Downloaded at pod start, never redistributed. |
| RITA v5 | GPL-3.0 | ✅ | — |
| ClickHouse | Apache-2.0 | ✅ | Don't use "ClickHouse" in the product name. |
| Vector | MPL-2.0 | ✅ | File-level copyleft only if you edit Vector's own files. |
| MISP | AGPL-3.0 | ✅ | AGPL network-source disclosure if you modify it. |
| Suricata | GPL-2.0 | ✅ | — |
| ET Open ruleset | BSD / GPLv2 (legacy SIDs) | ✅ | **Never ship SID ≥ 2800000** (that's proprietary ET Pro). We pull ET Open only. |
| Grafana / Loki | AGPL-3.0 | ✅ | Separate process, unmodified; naming caution. |
| Prometheus / Alloy | Apache-2.0 | ✅ | — |
| AdGuard Home | GPL-3.0 | ✅ | — |
| Spamhaus DROP | Free ToU (incl. commercial) | ✅ | **Attribution required**; keep the ©/date line. **Do NOT use "Spamhaus" in marketing.** |
| IEEE OUI data | factual (no license) | ✅ | Our `internal/oui` table is first-party (not Wireshark's GPL `manuf`). |
| First-party DHCP fingerprints | our own (GPL-3.0) | ✅ | `internal/dhcpfp` — not Fingerbank. |

## Standing obligations (do these before selling)

1. **Attribution:** DB-IP geolocation credit in the UI; Spamhaus DROP copyright
   line retained wherever the list is used.
2. **Trademark / naming — nominative use only, never in product name, domain,
   logo, or marketing copy:** Grafana®, Loki®, Prometheus®, ClickHouse,
   Suricata®, AdGuard®, Zeek (modified builds), and **Spamhaus** (strictest —
   keep it out of all sales/marketing material).
3. **Source disclosure (copyleft):** ship or offer the source of GPL/AGPL
   components you distribute in an appliance (AdGuard Home, RITA, ntopng CE,
   Suricata, MISP, Grafana, Loki) and of netSoldier itself (GPL-3.0).
4. **Set `COMMERCIAL_MODE=true`** so the abuse.ch feeds are disabled.
5. If you want abuse.ch or GreyNoise data in a commercial product, buy the
   respective commercial subscription and re-enable them.
