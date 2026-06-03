# 00 — Overview: projekt Argus

## Co budujemy
**Argus** — system do monitoringu domowego WiFi/LAN, który:
1. **Inwentaryzuje wszystkie urządzenia** w sieci (kto jest podłączony, jaki to sprzęt/OS).
2. Pokazuje **„kto → gdzie → czym" wysyła ruch** — DPI tam gdzie możliwe, analiza DNS, fingerprinting TLS/QUIC, rekordy flow.
3. **Flaguje złośliwe oprogramowanie i nietypowe wzorce** (sygnatury, threat-intel/IoC, beaconing C2, anomalie wolumetryczne).
4. Wykonuje **killswitch** — odcięcie/kwarantannę urządzenia przy wykryciu zagrożenia (tryb progowy, human-in-the-loop).

## Najwyższy priorytet
Program ma być **dopracowany produkcyjnie, ale to DevSecOps jest wizytówką**: Terraform, Docker, Kubernetes, pipeline CI/CD, IaC, security-pipeline na każdym commicie, SBOM/signing/SLSA, GitOps. Funkcjonalność sieciowa jest solidna, ale to platforma i pipeline mają być „bleeding edge" i bezbłędne.

## Filozofia budowy
**Hybryda**: używamy dojrzałych, gotowych silników (Suricata, Zeek, ntopng, AdGuard Home, RITA), ale piszemy **własną warstwę** korelacji detekcji, killswitcha, inwentaryzacji i UI oraz **w pełni własny DevSecOps**. NIE budujemy wszystkiego od zera (zbyt pracochłonne) i NIE adoptujemy gotowej platformy-pudełka (SELKS/Security Onion) — składamy własny system z najlepszych klocków.

## Charakter projektu
- Działa na własnej sieci domowej, za zgodą domowników (pełny monitoring dozwolony).
- Sprzęt testowy słaby (Raspberry Pi 3B+), docelowy normalny (serwer Proxmox ~8GB). Piszemy pod normalne środowisko; Pi dostaje okrojony profil „edge".
- Projekt portfolio/nauka + realne narzędzie — jakość produkcyjna end-to-end.

## Definicja „done" (production-grade)
Pełna ścieżka commit → CI (skan+SBOM+podpis+SLSA) → GHCR → ArgoCD → działający system na obu profilach; bezpieczny killswitch; testy (unit/integration/contract/e2e + replay PCAP); observability (metryki/logi/trace); SLO; DR/backup z przetestowanym restore; kompletna dokumentacja i audyty. Finał = tag `v1.0.0` po audycie końcowym.

Szczegóły: `01-environment-and-constraints.md`, `02-decisions.md`, `03-architecture.md`, `04-roadmap.md`, `05-research-findings.md`.
