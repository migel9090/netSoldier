# 03 — Architektura

## Diagram

```
                INTERNET
                   │
        ┌──────────┴───────────┐
        │  Router ISP (zamkn.)  │  ← jest też AP WiFi; DHCP wskazuje DNS = AdGuard (Pi/serwer)
        │  + WiFi radio         │
        └──────────┬───────────┘
                   │ uplink (mirror tego portu = ruch LAN↔net)
        ┌──────────┴───────────┐
        │  MANAGED SWITCH       │ ── SPAN/port-mirror ──► sensor (Pi/serwer)
        │  (SPAN + ACL/VLAN)    │ ◄── killswitch LAN: port-disable / quarantine-VLAN
        └──┬─────────┬──────────┘
   wired   │         │  (Faza 3: dedykowany AP → pełne DPI WiFi)
  devices ─┘         └─ AP / urządzenia
                   ▲
                   │ ARP-isolation (killswitch dla WiFi/wszystkich)
   ┌───────────────┴─────────────────────────────────────────────┐
   │  ARGUS — capture & detekcja (Pi edge  /  serwer „SOC")        │
   │  capture: AF_PACKET fanout (eBPF/XDP later) na SPAN          │
   │   ├─ Suricata 7/8  → EVE JSON (sygnatury ET Open + IoC)      │
   │   ├─ Zeek 8        → conn/dns/ssl/x509 + JA4 (metadane)      │
   │   ├─ ntopng        → L7 nDPI, flow real-time                 │
   │   └─ AdGuard Home  → DNS per-client + sinkhole               │
   │  korelacja (Go): detection-engine ──► ClickHouse            │
   │   ├─ device-inventory (DHCP opt55/60 + mDNS + ARP + OUI)    │
   │   ├─ threat-intel matcher (MISP: ThreatFox/GreyNoise/Spamhaus)│
   │   └─ killswitch-controller (progowy, human-in-the-loop)     │
   │  ML (Python): RITA (beaconing C2) + Isolation Forest (exfil)│
   │  dane: ClickHouse (flow/event) + Loki (logi) + Prometheus   │
   │  prezentacja: Grafana + własny frontend (SvelteKit)         │
   │  egzekucja: AdGuard sinkhole / ARP-isolation / switch ACL   │
   │  alert: generyczny webhook                                  │
   └──────────────────────────────────────────────────────────────┘
     Kontenery multi-arch → k3s+ArgoCD (serwer) / Podman (Pi)
```

## Stack technologiczny (warstwa → wybór → uwaga Pi)

| Warstwa | Wybór | Pi 3B+ (edge) |
|---|---|---|
| Capture | AF_PACKET fanout (gopacket); eBPF/XDP później na serwerze | działa, limit USB2/CPU |
| DNS | AdGuard Home | ✅ natywnie |
| DPI sygnatury | Suricata 7/8 (EVE JSON, ET Open) | okrojony ruleset lub OFF |
| Metadane | Zeek 8 (conn/dns/ssl + JA4) | OFF na Pi (RAM) — serwer |
| L7 real-time | ntopng (nDPI) | tylko jeśli zasoby pozwolą |
| Beaconing C2 | RITA v5.1 (backend ClickHouse) | serwer only |
| Anomalia wolumetria | Isolation Forest (scikit-learn) | lekki, opcjonalnie |
| Threat-intel | MISP + abuse.ch/GreyNoise/Spamhaus | match na serwerze |
| Storage | ClickHouse (hot 30d) + MinIO/S3 (cold) | Pi → Fluent Bit |
| Pipeline logów | Fluent Bit (edge) → Vector (serwer) | ✅ Fluent Bit <10MB |
| Metryki/logi/trace | Prometheus + Loki + Grafana Alloy + OTel | exporter+Alloy na Pi |
| Wizualizacja | Grafana + frontend SvelteKit | serwer |
| Usługi własne | Go | binar arm64 |
| ML | Python (FastAPI) | serwer |

## Struktura repo (monorepo)

```
projektMigel/
├── apps/
│   ├── detection-engine/        # Go: EVE/Zeek/ntopng → korelacja → ClickHouse
│   ├── device-inventory/        # Go: DHCP opt55/60 + mDNS + ARP + OUI → SQLite/ClickHouse
│   ├── killswitch-controller/   # Go: polityka progowa, allowlist, audyt; sterowniki egzekucji
│   ├── threat-intel-sync/       # Go: MISP/feeds → reguły Suricata + listy AdGuard
│   ├── ml-anomaly/              # Python/FastAPI: RITA glue + Isolation Forest
│   └── web-ui/                  # SvelteKit: mapa urządzeń, alerty, zatwierdzanie killswitcha
├── deploy/
│   ├── helm/argus/              # umbrella chart
│   ├── kustomize/{base,overlays/{pi-edge,proxmox-soc}}
│   ├── argocd/                  # app-of-apps, ApplicationSet
│   ├── kyverno/                 # policy: podpisy obrazów, non-root, limits
│   └── podman/                  # Quadlets/compose dla Pi
├── infra/
│   ├── terraform/               # Proxmox (bpg/proxmox): VM k3s, sieci, storage
│   └── ansible/                 # bootstrap+hardening, k3s/Podman, cloud-init
├── detections/
│   ├── suricata/                # reguły + lokalny ruleset z threat-intel
│   ├── zeek/                    # skrypty (JA4, Intel framework)
│   └── pcap-corpus/             # próbki PCAP do testów CI (lub manifest pobierania)
├── observability/               # dashboardy Grafana, reguły Prometheus/Loki, OTel config
├── security/                    # polityki SOPS, .sops.yaml, baseline skanerów
├── .github/workflows/           # CI/CD (build multi-arch, security gate, SBOM, sign, deploy)
├── .pre-commit-config.yaml
├── docs/                        # ADR, architektura, runbooki, threat-model, audyty
└── README.md
```

## Pipeline DevSecOps (skrót — pełne kroki w 04-roadmap.md)
- **Pre-commit**: gitleaks + semgrep + checkov + hadolint + formattery.
- **CI na PR**: Harden-Runner + akcje pinowane do SHA → lint/test → SAST (Semgrep+CodeQL) → SCA (OSV-Scanner+Grype) → IaC (Checkov+KICS) → secrets (gitleaks) → build multi-arch (buildx → GHCR) → SBOM (Syft/CycloneDX) → cosign keyless + SLSA L2 → bramka (blok critical/high; sekrety zawsze blok) → **replay PCAP** (detection-as-code).
- **GitOps**: ArgoCD app-of-apps + ApplicationSet (profile pi-edge/proxmox-soc); Kyverno verifyImages (tylko podpisane), non-root, RO-FS, limits; sekrety SOPS+age.
- **IaC**: Terraform (bpg/proxmox) → VM k3s + sieci/storage; Ansible → bootstrap OS + hardening + k3s/Podman.
- **Dependency hygiene**: Renovate/Dependabot, **automerge OFF**, wymagany review.

## Fazy (mapa)
- **Faza 0 (0–50):** fundament DevSecOps + cienki pionowy plaster.
- **Faza 1 (51–100):** pełny lekki MVP funkcjonalny.
- **Faza 2 (101–150):** ciężka analiza na serwerze (Suricata/Zeek/RITA/ML/ClickHouse) + production-readiness.
- **Faza 3 (151–172):** hardening i rozbudowa → v1.0.0.
Audyty: 25, 50, 75, 100, 125, 150, 172.
