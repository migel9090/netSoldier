# Argus

> Home-network security monitor: device inventory, traffic visibility (*who → where → what*),
> threat detection, and a human-in-the-loop killswitch — built end-to-end as a
> production-grade **DevSecOps showcase**.

## What it does

- **Inventories every device** on the home LAN/WiFi (DHCP fingerprinting, mDNS, ARP/OUI, Fingerbank) — resilient to MAC randomization.
- **Shows who → where → what**: per-device DNS, flow records and L7 metadata from a SPAN tap (Suricata, Zeek, ntopng), TLS/QUIC fingerprinting (JA4) — **metadata only, no MITM**.
- **Flags malware & anomalies**: IoC feeds (abuse.ch, GreyNoise, Spamhaus → MISP), C2 beaconing (RITA), volumetric anomalies (Isolation Forest), composite confidence scoring.
- **Quarantines threats** via an out-of-band killswitch (DNS sinkhole → ARP isolation → managed-switch ACL) — threshold-based, **human-in-the-loop**, with allowlist (fail-open), TTL auto-revert and a full audit log.

## How it's built (the actual showcase)

Monorepo with a bleeding-edge supply-chain-hardened pipeline: GitHub Actions (SHA-pinned, Harden-Runner) → SAST (Semgrep, CodeQL) + SCA (OSV-Scanner, Grype) + IaC scan (Checkov, KICS) + secrets (gitleaks, TruffleHog) → multi-arch images (amd64+arm64) → SBOM (Syft/CycloneDX) → cosign keyless signing + SLSA L2 provenance → GitOps (ArgoCD app-of-apps, Kyverno `verifyImages`) → k3s (server) / Podman Quadlets (edge). Infrastructure via Terraform (`bpg/proxmox`) + Ansible; secrets via SOPS+age; detections regression-tested with PCAP replay in CI; full observability (Prometheus, Grafana, Loki, Alloy, OTel).

## Architecture

Hybrid: mature open-source engines (Suricata, Zeek, ntopng, AdGuard Home, RITA, MISP, ClickHouse) + a custom Go/Python correlation-and-control plane (`detection-engine`, `device-inventory`, `threat-intel-sync`, `killswitch-controller`, `ml-anomaly`, SvelteKit `web-ui`). Two deployment profiles: `proxmox-soc` (full stack, ~8 GB server) and `pi-edge` (minimal, Raspberry Pi).

Full context, decisions, architecture and the 173-step roadmap: [`context/`](context/).

## Status

Phase 0 (DevSecOps foundation) in progress — see the [173-step roadmap](context/04-roadmap.md).
Conventions for commits, branching and reviews: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Ethics & privacy

Argus monitors the **author's own home network with household consent** (defensive/educational). Passive IDS, out-of-band response only, human-in-the-loop quarantine with allowlist and audit trail, metadata-only visibility (no payload inspection, no MITM), 30-day default retention.

## License

[GNU GPL-3.0](LICENSE) — free software, free for commercial use; copyleft applies to derivatives.
