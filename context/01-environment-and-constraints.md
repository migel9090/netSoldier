# 01 — Środowisko i ograniczenia

## Sprzęt
- **Raspberry Pi 3B+** — obecny sprzęt testowy/edge. 4× Cortex-A53 @1.4GHz, **1 GB RAM**, NIC Gigabit **na magistrali USB2 (~300 Mbps realnie, jeden port)**, WiFi 2.4/5GHz. 64-bit-capable → **wymagany 64-bit OS (Raspberry Pi OS 64-bit / Ubuntu arm64)** dla obrazów arm64. Akceptowany throttling.
- **Serwer Proxmox** — docelowy/showcase. Założenie: **~8 GB RAM / 4 vCPU** (x86-64). Tu działa pełny stack (ciężkie DPI, ML, ClickHouse, k3s+ArgoCD).
- Konsekwencja: **piszemy pod normalne środowisko (4–8 GB)**, Pi 3B+ to tylko maszynka testowa z profilem „edge/minimal". Obrazy **multi-arch amd64+arm64**.

## Sieć
- **Router ISP** — zamknięty (brak API, brak SPAN, brak NetFlow). Jest jednocześnie **bramą, serwerem DHCP i punktem dostępowym WiFi**.
- **Managed switch** — dokupowany. Daje: **SPAN/port-mirror** (pasywny tap) oraz egzekucję killswitcha dla urządzeń przewodowych (disable portu / quarantine-VLAN / ACL).

## Topologia i tap (jak netSoldier widzi ruch)
- **Warstwa DNS (wszystkie urządzenia, w tym WiFi):** Pi/serwer jako resolver **AdGuard Home**; router ISP w DHCP wskazuje go jako DNS (lub DHCP na netSoldierie). Daje pełną widoczność zapytań DNS per-urządzenie + sinkhole.
- **Warstwa pakietowa (LAN/przewodowe):** **SPAN na managed switchu** → sensor (AF_PACKET fanout) → Suricata/Zeek/ntopng.
- **Flow** wyprowadzamy z SPAN (Zeek/Suricata/ntopng), **NIE** z routera (router ISP nie eksportuje NetFlow).

## Ważne ograniczenie: widoczność WiFi
Router ISP jest też AP — ruch **WiFi→internet idzie wewnątrz routera ISP i NIE przechodzi przez downstream switch**, więc SPAN nie zobaczy go pakietowo. Decyzja: na razie WiFi ma widoczność **DNS + metadane**, a **pełne DPI WiFi** dokładamy w Fazie 3 przez **dedykowany AP za switchem** (przeniesienie WiFi za switch). Urządzenia przewodowe mają pełne DPI od razu.

## Killswitch — punkty egzekucji (out-of-band)
1. **DNS-sinkhole** (AdGuard API) — najszybsze, działa dla wszystkich (w tym WiFi).
2. **ARP-isolation** — odcięcie L2 dowolnego urządzenia (w tym WiFi), z auto-revert po TTL.
3. **Managed switch** (SNMP/REST/SSH) — disable portu / quarantine-VLAN dla przewodowych.

## Budżet zasobów (profil `proxmox-soc`, 8 GB)
Twarde requests/limits. Orientacyjnie: ClickHouse ~2–3 GB, Suricata ~1–1.5 GB (ograniczony ruleset), Zeek 1 worker ~1 GB, Grafana ~0.5 GB, reszta ~1.5 GB. Przy ciasnocie Zeek/Arkime warunkowo (feature-flag w Helm values). Profil `pi-edge`: tylko AdGuard + device-inventory + Fluent Bit + (opcjonalnie) lekka detekcja.

## Prywatność / legalność
Własna sieć, zgoda domowników → pełny monitoring dozwolony. Bez MITM (tylko metadane) → brak inspekcji payloadu. Retencja domyślnie 30 dni (konfigurowalna).
