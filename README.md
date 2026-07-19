# netSoldier

> Home-network security monitor: device inventory, traffic visibility (*who → where → what*),
> threat detection, and a human-in-the-loop killswitch.

## What it does

- **Inventories every device** on the home LAN/WiFi (DHCP fingerprinting, mDNS, ARP/OUI, Fingerbank) — resilient to MAC randomization.
- **Shows who → where → what**: per-device DNS, flow records and L7 metadata from a SPAN tap (Suricata, Zeek, ntopng), passive TLS/QUIC client fingerprinting (JA4-format, first-party clean-room) — **metadata only, no MITM**.
- **Flags malware & anomalies**: IoC feeds (abuse.ch, GreyNoise, Spamhaus → MISP), C2 beaconing (RITA), volumetric anomalies (Isolation Forest), composite confidence scoring.
- **Quarantines threats** via an out-of-band killswitch (DNS sinkhole → ARP isolation → managed-switch ACL) — threshold-based, **human-in-the-loop**, with allowlist (fail-open), TTL auto-revert and a full audit log.

## Architecture

Hybrid: mature open-source engines (Suricata, Zeek, ntopng, AdGuard Home, RITA, MISP, ClickHouse) + a custom Go/Python correlation-and-control plane (`detection-engine`, `device-inventory`, `threat-intel-sync`, `killswitch-controller`, `ml-anomaly`, SvelteKit `web-ui`). Two deployment profiles: `proxmox-soc` (full stack, ~8 GB server) and `pi-edge` (minimal, Raspberry Pi).

## Tech stack

Monorepo. Go services (pure, no CGO), Python ML, SvelteKit UI. CI via GitHub Actions (SHA-pinned, Harden-Runner), SAST/SCA/IaC scanning, multi-arch container images (amd64+arm64), SBOM, cosign signing, SLSA provenance. GitOps with ArgoCD + Kyverno image verification. Infrastructure: Terraform (Proxmox) + Ansible, k3s on server, Podman Quadlets on edge. Secrets via SOPS+age. Observability: Prometheus, Grafana, Loki, Alloy, OpenTelemetry. Detection regression tested with PCAP replay in CI.

## Status

Work in progress — see the 173-step roadmap.
Conventions for commits, branching and reviews: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Ethics & privacy

netSoldier monitors the **author's own home network with household consent** (defensive/educational). Passive IDS, out-of-band response only, human-in-the-loop quarantine with allowlist and audit trail, metadata-only visibility (no payload inspection, no MITM), 30-day default retention.

## License

[GNU GPL-3.0](LICENSE) — free software, free for commercial use; copyleft applies to derivatives.
