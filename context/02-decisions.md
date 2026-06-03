# 02 — Decyzje architektoniczne (z 7-rundowego wywiadu, 28 rozstrzygnięć)

Te decyzje są **zatwierdzone przez użytkownika**. Nie podważaj ich bez wyraźnej zgody — jeśli coś wydaje się sprzeczne z nowymi faktami, zapytaj.

| # | Obszar | Decyzja |
|---|---|---|
| 1 | Posture | Pasywny **IDS** + killswitch **out-of-band** |
| 2 | Filozofia | **Hybryda**: gotowe silniki (Suricata/Zeek/ntopng/AdGuard/RITA) + własna warstwa korelacji/killswitch/UI + własny DevSecOps |
| 3 | Priorytet | Wszystko produkcyjnie; **DevSecOps = wizytówka** |
| 4 | Sprzęt | Pi 3B+ (edge/test, throttling OK) + serwer Proxmox ~8GB/4vCPU (docelowy). Piszemy pod normalne środowisko |
| 5 | Router | Zamknięty router ISP (też AP WiFi) + **dokupowany managed switch** (SPAN + ACL/VLAN/port) |
| 6 | Widoczność | AdGuard DNS dla wszystkich + SPAN packet-capture dla LAN; pełne DPI WiFi po dołożeniu AP za switchem (Faza 3) |
| 7 | Głębia DPI | Lekki pełny MVP teraz → ciężkie DPI/ML/ClickHouse na serwerze |
| 8 | Prywatność | Pełny monitoring OK (własna sieć, zgoda) |
| 9 | TLS/szyfrowanie | **Tylko metadane**: JA4/JA3 + SNI + DNS (bez MITM) |
| 10 | Detekcja | Pełna: Suricata + Zeek + ntopng + **RITA** (beaconing) + Isolation Forest (wolumetria) |
| 11 | Threat-intel | abuse.ch (ThreatFox/URLhaus/Feodo) + GreyNoise Community + Spamhaus → agregacja w **MISP** |
| 12 | Killswitch | **Progowy / human-in-the-loop**: auto-block tylko high-confidence IoC/sygnatura + DNS-sinkhole; anomalie → alert + zatwierdzenie; allowlist (fail-open); audyt akcji |
| 13 | Egzekucja | DNS-sinkhole (AdGuard) + ARP-isolation + managed-switch ACL/port/VLAN (LAN) |
| 14 | DNS | **AdGuard Home** |
| 15 | Storage | **ClickHouse** (serwer); Pi wysyła przez Fluent Bit; SQLite na inwentarz edge |
| 16 | Język | **Go** (usługi) + **Python** (mikroserwis ML) |
| 17 | UI | **Grafana** (dashboards-as-code) + lekki własny frontend **SvelteKit** (mapa urządzeń + zatwierdzanie killswitcha) |
| 18 | Alerty | **Generyczny webhook**; retencja domyślnie ~30 dni hot + opcjonalnie cold MinIO/S3 |
| 19 | Orkiestracja | Cel **k3s + ArgoCD**; Pi = lekki profil **Podman Quadlets/compose** (te same obrazy) |
| 20 | IaC | **Terraform + Ansible + cloud-init**; provider Proxmox `bpg/proxmox` |
| 21 | Git/CI | **GitHub + GitHub Actions** (self-hosted arm64 runner do buildów) |
| 22 | GitOps | **ArgoCD** (app-of-apps + ApplicationSet: profile pi-edge / proxmox-soc) |
| 23 | Sekrety | **SOPS + age** (GitOps-friendly) |
| 24 | Repo | **Monorepo** |
| 25 | Admission | **Kyverno** (verifyImages cosign, non-root, RO-FS, limits) |
| 26 | Gate CI | Blokuj **critical/high**, ostrzegaj medium; sekrety zawsze blok |
| 27 | Testy detekcji | **Replay PCAP** w CI (korpus malware-traffic + testy Suricata) |
| 28 | Observability | Pełny: **Prometheus + Grafana + Loki + Grafana Alloy + OTel tracing** |

## Dodatkowe ustalenia (baked-in, research-backed)
- **Skanery**: SCA = OSV-Scanner + Grype (**NIE Trivy** — research flagował incydent supply-chain III 2026, do weryfikacji, ale OSV+Grype to bezpieczny default). SAST = Semgrep + CodeQL. IaC = Checkov + KICS. Secrets = gitleaks (pre-commit+CI) + TruffleHog (nightly). Dockerfile = hadolint. Manifesty = kubeconform + kube-linter.
- **Supply chain**: SBOM Syft/CycloneDX, cosign keyless (Sigstore/OIDC), SLSA L2 provenance, Harden-Runner, akcje pinowane do SHA, Renovate/Dependabot z **automerge OFF**.
- **Registry**: GHCR. **Pipeline logów**: Fluent Bit (edge) → Vector (serwer) → ClickHouse + Loki. **OS**: Debian 12/Ubuntu 24.04 (serwer), Raspberry Pi OS 64-bit (Pi). **Capture**: AF_PACKET fanout (eBPF/XDP jako późniejszy boost).
- **Fazowanie**: DevSecOps-foundation-first + cienki pionowy plaster → pełny lekki MVP → ciężkie DPI/ML na serwerze → hardening.
