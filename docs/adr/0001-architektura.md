# ADR-0001: Core architecture of Argus (interview decisions)

- **Date:** 2026-06-03
- **Status:** Accepted
- **Deciders:** project owner (7-round technical interview, June 2026)

## Context and problem

Argus is a greenfield home-network security monitor: device inventory, *who→where→what*
traffic visibility, threat detection, and a quarantine killswitch — with a
production-grade DevSecOps pipeline as the explicit showcase. Hard constraints:

- **Closed ISP router** (no API, no SPAN, no NetFlow) that is also the WiFi AP;
  a **managed switch** (SPAN + ACL/VLAN, to be purchased) provides the tap and wired enforcement.
- Hardware: **Raspberry Pi 3B+** (1 GB, USB2 NIC) as edge/test; **Proxmox server ~8 GB/4 vCPU**
  as the target — we design for 4–8 GB, the Pi gets a minimal profile.
- **Privacy:** own network, household consent; no payload inspection.

Decisions below were made in a 7-round interview, informed by a 10-domain bleeding-edge
research sweep (2024–2026). Authoritative Polish record: [`context/02-decisions.md`](../../context/02-decisions.md)
(28 decisions); research basis and deliberate divergences from raw research
recommendations: [`context/05-research-findings.md`](../../context/05-research-findings.md).

## Decision

**Posture & philosophy**
1. **Passive IDS + out-of-band killswitch** — the sensor is never inline; a sensor failure can never take the network down (fail-open by design).
2. **Hybrid build**: mature engines (Suricata, Zeek, ntopng, AdGuard Home, RITA, MISP) + a custom correlation/control plane and fully custom DevSecOps. No boxed platform (SELKS/Security Onion), no from-scratch engines.
3. Everything production-grade; **DevSecOps is the portfolio centerpiece**.

**Visibility**
4. DNS chokepoint: **AdGuard Home** as resolver for all clients (incl. WiFi) — per-device query log + sinkhole; DNS-first strategy anticipates ECH/DoH blindness.
5. Packet visibility for wired LAN via **SPAN port-mirror** on the managed switch; flow derived from SPAN (router exports nothing).
6. **WiFi packet-level DPI deferred to Phase 3** (dedicated AP behind the switch); until then WiFi has DNS + metadata visibility only.
7. **TLS metadata only: JA4/JA3 + SNI + DNS — no MITM**, no payload inspection.

**Detection**
8. Engines: **Suricata 7/8** (ET Open signatures + IoC datasets) + **Zeek 8** (conn/dns/ssl/x509, JA4, Intel framework) + **ntopng** (nDPI L7) on the server profile.
9. Behavioral layer: **RITA v5.1** (C2 beaconing, ClickHouse backend) + **Isolation Forest** (volumetric/exfil anomalies) in a Python ML microservice.
10. Threat intel: **abuse.ch (ThreatFox/URLhaus/Feodo) + GreyNoise Community + Spamhaus → aggregated in MISP**, exported to AdGuard lists, Suricata datasets, Zeek Intel.
11. Signals fuse into a **composite confidence score** (signature + beaconing + volumetric + JA4 + IoC) — single weak signals never trigger enforcement.

**Killswitch**
12. **Threshold-based, human-in-the-loop**: auto-block only for high-confidence IoC/signature matches and only via DNS-sinkhole; everything else queues for explicit approval. **Allowlist of critical devices (fail-open), TTL auto-revert, append-only audit log.**
13. Enforcement drivers, out-of-band: **AdGuard DNS-sinkhole → ARP-isolation → managed-switch ACL/port/VLAN**.

**Platform & data**
14. Storage: **ClickHouse** (hot, default 30-day retention; optional cold MinIO/S3). Edge buffers via **Fluent Bit → Vector** (server) pipeline; SQLite cache for edge inventory.
15. Languages: **Go** for services, **Python (FastAPI)** for ML; UI = **Grafana** (dashboards-as-code) + **SvelteKit** frontend (device map, approvals); alerts via **generic webhook**.
16. Orchestration: **k3s + ArgoCD** (server, GitOps app-of-apps + ApplicationSet) / **Podman Quadlets** (Pi) — same multi-arch images (amd64+arm64), profiles `proxmox-soc` & `pi-edge` via Kustomize overlays.
17. IaC: **Terraform (`bpg/proxmox`) + Ansible + cloud-init**; CI on **GitHub Actions** (self-hosted arm64 runner); secrets **SOPS + age**; **monorepo**; admission control **Kyverno** (cosign verifyImages, non-root, RO-FS, limits).

**Pipeline gates (research-backed addenda)**
18. SCA: **OSV-Scanner + Grype — explicitly not Trivy** (its repo was compromised twice in March 2026); SAST: Semgrep + CodeQL; IaC: Checkov + KICS; secrets: gitleaks (pre-commit+CI) + TruffleHog (nightly); Dockerfiles: hadolint.
19. Supply chain: SBOM (Syft/CycloneDX), **cosign keyless** signing, **SLSA L2** provenance, Harden-Runner egress monitoring, all actions **pinned to commit SHAs**, Renovate/Dependabot with **automerge OFF** (auto-merged dep updates amplified the Axios 1.7.7 attack to 895+ repos).
20. CI gate blocks **critical/high** findings and any secret; detection rules are regression-tested by **PCAP corpus replay** in CI.
21. Observability is full-stack from day one: Prometheus + Grafana + Loki + **Grafana Alloy** (Promtail is EOL 2026) + OpenTelemetry tracing.

## Alternatives considered

| Option | Why not |
|---|---|
| Boxed platform (SELKS 10 / Security Onion) | retention limits, lock-in, hides exactly the custom DevSecOps + control plane this project exists to showcase |
| Inline IPS (Suricata NFQUEUE / XDP_DROP killswitch) | inline sensor = household outage risk on failure; out-of-band + fail-open is the safety requirement |
| Wazuh as SIEM/orchestration hub | manager needs 3 GB+ RAM — doesn't fit the 8 GB budget; duplicates the custom layer (optional at 32 GB+, roadmap step 154) |
| OpenTofu (research favored it over Terraform's BSL) | `bpg/proxmox` works with both; Terraform chosen, migration stays cheap if licensing bites |
| Home Assistant / Node-RED for approvals & UI | full control over the human-in-the-loop approval path is a core deliverable, not glue code |
| MITM TLS inspection | privacy violation in a household; metadata (JA4+DNS) suffices for the threat model |
| Pi-hole v6 for DNS | needs an Unbound sidecar for DoH/DoT/DoQ; AdGuard Home is a single binary with per-client filtering |

Full divergence table (9 entries): `context/05-research-findings.md` → „Rozbieżności".

## Consequences

- **Positive:** sensor failure cannot break the network; enforcement is reversible (TTL) and audited; privacy-preserving by construction; reproducible from bare metal (IaC + GitOps); supply-chain attacks mitigated at multiple layers; detections are regression-tested like code.
- **Negative / accepted trade-offs:** no WiFi packet DPI until Phase 3 (DNS/metadata only); 8 GB forces strict resource budgets and feature-flags (Zeek/Arkime conditional); a custom control plane is more code to own and test; ECH will erode SNI visibility (~50% of clients by ~2026) — mitigated by the DNS-first design; out-of-band enforcement reacts in seconds, not microseconds (acceptable for a home network).
- **Follow-ups:** STRIDE threat model (step 4); audit gates at steps 25/50/75/100/125/150/172; managed-switch purchase unblocks steps 64/72.

## Links

- [`context/02-decisions.md`](../../context/02-decisions.md) — authoritative decision record (PL)
- [`context/05-research-findings.md`](../../context/05-research-findings.md) + [`context/research-raw.json`](../../context/research-raw.json) — research basis
- [`context/04-roadmap.md`](../../context/04-roadmap.md) — 173-step execution plan
- [`context/01-environment-and-constraints.md`](../../context/01-environment-and-constraints.md) — hardware/network constraints
