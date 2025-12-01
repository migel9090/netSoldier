# 05 — Research findings: bleeding-edge 2024–2026 (10 domen + synteza)

## Pochodzenie i jak czytać ten plik

Wyniki głębokiego researchu (10 równoległych strumieni + synteza, 11 agentów, workflow `wf_74fc0ed0-f1d`, czerwiec 2026), który był **wejściem** do 7-rundowego wywiadu decyzyjnego. Ten plik to skondensowana destylacja surowego wyniku — pełny surowy output (~358 KB JSON, z pros/cons per technologia i otwartymi pytaniami) zarchiwizowany w `context/research-raw.json`.

**Ważne:** research poprzedzał decyzje. Tam, gdzie finalna decyzja (z `02-decisions.md`) świadomie odbiega od rekomendacji researchu, obowiązuje **decyzja** — pełna lista rozbieżności w sekcji „Rozbieżności" na końcu. Daty i wersje odzwierciedlają stan wiedzy z momentu researchu (VI 2026).

---

## Domena 1 — Capture i kernel datapaths (libpcap, AF_PACKET, AF_XDP, eBPF/XDP, PF_RING, DPDK)

- **AF_PACKET fanout (TPACKET_V3)** = battle-tested baseline na x86 **i** ARM64, bez problemów driverowych; polityka `PACKET_FANOUT_QM` (kernel 5.9+) daje 20–30% redukcji CPU przez alignment z NIC RSS.
- **Suricata 7.0+ z natywną integracją eBPF/XDP** (II 2025): XDP_DROP w warstwie drivera, bez userspace proxy — ale wymaga wsparcia w driverze NIC (Intel i40e/ice tak; **RTL8111 i NIC-i konsumenckie/Pi — nie**).
- Kernel 6.6+: XDP multi-buffer (jumbo frames); DPDK 24.11 skaluje do 186 Gb/s — **overkill**; PF_RING ZC ma szarą strefę licencyjną; netmap legacy — wszystkie trzy odrzucone.
- **SPAN/port-mirror na managed switchu** = sprzętowa replikacja zero-overhead; `tc mirred` dla ruchu east-west na bridge'ach Proxmoksa.
- Tetragon 1.2+/Falco (eBPF runtime security) — opcja ochrony samego sensora; Tetragon policy-as-code wypiera shell-scripty.

**→ Decyzje:** AF_PACKET fanout od startu (krok 64), eBPF/XDP jako boost dopiero w Fazie 3 (krok 151), tap = SPAN z managed switcha.

## Domena 2 — Silniki DPI i flow (Suricata, Zeek, ntopng, Arkime, eksportery flow)

- **Suricata** stable 7.0.11 (2025); linia 8.x wnosi dataset/datajson context i transactional rules; 9.x — strumienie researchu niespójne (raz „dev", raz „released 2024") → w decyzjach konserwatywnie **Suricata 7/8**.
- **Zeek** 7.0.9 (I 2025, natywne JA4 + QUIC) / 8.0 (VIII 2025, elastyczny clustering ZeroMQ); rola: forensic metadata + Intel framework; fuzja Zeek+Suricata z korelacją SIEM ≈ 91% accuracy detekcji (2025).
- **ntopng/nDPI**: lekki L7 real-time, integracja ClickHouse (2025); pmacct 1.7.9, GoFlow2 (NATS JetStream CEP) — alternatywy flow, niepotrzebne przy SPAN.
- **Arkime 5** (VI 2024): JA4, conditional/offline PCAP, S3 — warstwa forensyczna, zasobożerna.
- Wniosek researchu: **hybryda Suricata (sygnatury) + Zeek (metadane/behawior) + ntopng (widoczność L7)** — komplementarne, nie redundantne.

**→ Decyzje:** #10 (pełna detekcja trzema silnikami), Arkime tylko opcjonalnie w Fazie 3 (krok 155).

## Domena 3 — TLS/szyfrowany ruch: fingerprinting i widoczność (JA4, ECH, QUIC, DoH/DoT/DoQ, DNS)

- **JA3 jest martwe** dla nowoczesnego ruchu (randomizacja ClientHello w Chrome); **JA4+** (JA4/JA4S/JA4H/JA4X; JA4 na BSD, część wariantów na licencji FoxIO) = standard 2024–2025; JARM pozostaje server-side standardem dla C2; JA4T dla QUIC — emerging.
- **ECH (RFC 9849, final 2024)**: rollout Cloudflare od IX 2024; szacunkowo ~50% klientów do 2026 → **ślepota na SNI**. Reguły oparte na SNI przestaną działać.
- **QUIC/HTTP3** dominuje; Zeek 7.0.9 i Suricata 7.0.11 mają natywną dyssekcję QUIC; DoQ (RFC 9250) najtrudniejszy do przechwycenia/blokady.
- **Strategia DNS-first**: logowanie DNS **przed** szyfrowaniem (własny resolver) to ostatni pewny punkt widoczności („ground truth"); korelacja DNS↔JA4 w oknie czasowym łamie ślepotę ECH. Mitygacje bypassu: blok portu 853 (DoT), denylist znanych endpointów DoH.
- **AdGuard Home > Pi-hole v6**: pojedynczy binar Go, natywne DoH/DoT/DoQ, per-client filtering; Pi-hole nadal wymaga sidecar-Unbound (dług architektoniczny).
- **MITM odrzucony** dla głównego ruchu (prywatność); ewentualnie izolowany VLAN incident-response — nie wdrażamy.

**→ Decyzje:** #9 (tylko metadane: JA4/JA3+SNI+DNS, bez MITM), #14 (AdGuard Home), kroki 106, 110.

## Domena 4 — Inwentaryzacja urządzeń (DHCP fingerprinting, mDNS, ARP/OUI, Fingerbank, randomizacja MAC)

- **DHCP fingerprinting (opt 55 Parameter Request List + opt 60 Vendor Class ID)** = fundament pasywnej inwentaryzacji: niski szum, wysoka trafność klasyfikacji OS/typu.
- **Fingerbank w trybie lokalnym** (110K+ modeli urządzeń, 6M+ fingerprintów, wykrywanie MAC-spoofingu) jako enrichment; pełny PacketFence NAC — overkill.
- mDNS/Avahi (przyjazne nazwy), SSDP/UPnP, LLDP, ARP-scan (rekonsyliacja), p0f (pasywny OS-fingerprint dla urządzeń ze statycznym IP — łata blind spot DHCP).
- **Randomizacja MAC (iOS 14+/Android 10+)**: tożsamość urządzenia wiązać po `hostname + opt60` (+ rezerwacje DHCP), nie po MAC.
- Blind spot: urządzenia ze statycznym IP nigdy nie przechodzą DHCP → p0f + ARP-rekonsyliacja + ręczna allowlista.

**→ Decyzje:** kroki 42, 57–60 (`device-inventory`); model danych ze stabilnym ID niezależnym od MAC.

## Domena 5 — Threat-intel i IoC (MISP, abuse.ch, GreyNoise, Spamhaus, YARA/Sigma, STIX/TAXII)

- **MISP** jako centralny agregator IoC — prostszy niż OpenCTI w skali home-lab, ma bezpośredni eksport do Suricata/Zeek; v2.5.37+ (IV 2026): natywny typ atrybutu Suricata + duże optymalizacje wydajności. OpenCTI (score decay v6.0) — trend wart obserwacji.
- Feedy darmowe na start: **abuse.ch ThreatFox/URLhaus/Feodo** (od 2025-05-01 auto-expiry IoC >6 mies. — wymusza świeżość), **GreyNoise Community** (reputacja skanerów; Global Observation Grid: 5000 sensorów, 500M sesji/dzień), **Spamhaus DROP/EDROP**.
- **Suricata 8.0 dataset/datajson context**: metadane IoC (źródło, severity, tagi MITRE ATT&CK) osadzone bezpośrednio w alercie — zero-lookup enrichment, bez opóźnień SIEM.
- Synchronizacja IoC co godzinę; cel świeżości <6 h. YARA (pliki) i Sigma (logi) — uzupełnienia; AI-generowanie reguł Sigma (SigmaGen) — emerging. STIX/TAXII — dopiero przy rozbudowie.

**→ Decyzje:** #11 (abuse.ch+GreyNoise+Spamhaus→MISP), kroki 52–56, 103, 134; STIX/TAXII w kroku 156.

## Domena 6 — Behawioralna/ML detekcja anomalii (RITA, Isolation Forest, DGA, Kitsune, PyOD)

- **RITA v5.1 (V 2026, backend ClickHouse zamiast MongoDB)** = złoty standard detekcji beaconingu C2 (z obsługą jittera); rolling imports → monitoring ciągły. FP na sieciach domowych: **0,1–0,5%**.
- **Isolation Forest** (scikit-learn) na cechach wolumetrycznych (bytes/duration/fanout): 93–95% accuracy, lekki; FP **2–5%** bez filtrowania kontekstem (pora dnia, allowlisty).
- **Detekcja DGA** (LSTM/ensembles): 98%+ accuracy na znanych rodzinach, ale FP **5–15%** (literówki, nowe CDN-y) → tylko sygnał średniej pewności.
- **Composite ensemble — kluczowy wniosek:** wymaganie ≥2 niezależnych sygnałów (np. beaconing **i** wolumetria) zbija FP do **0,01–0,1%** — dopiero to nadaje się na próg auto-killswitcha. Hierarchia pewności: Tier 1 beaconing+JA4 (high) → Tier 2 wolumetria (medium) → Tier 3 DGA (medium-low).
- Kitsune (autoencodery, jest port PyTorch 2024), PyOD 2.0 (XII 2024, 60+ algorytmów, unified PyTorch backend), PyGOD/DeepOD (grafowe/deep) — research-stage; marginalne +5–10% precyzji za dużą złożoność → moduły opcjonalne.
- Znane wektory unikania: jittered beaconing (RITA wykrywa z niższą pewnością), low-and-slow exfil (<1 MB/h — detekcja w tygodniach), C2 przez VPN/proxy.

**→ Decyzje:** #10/#12 (RITA + Isolation Forest; composite-confidence steruje progami killswitcha — kroki 111–117), Kitsune/autoencoder w kroku 157.

## Domena 7 — Killswitch i izolacja urządzeń (nftables, NFQUEUE, VLAN, DAI, API vendorów)

- **nftables dynamic sets + atomowe add/remove (kernel 5.10+)**: egzekucja sub-milisekundowa, `timeout` z auto-expiry (TTL) wbudowanym w kernel, **fail-open** (reguły żyją niezależnie od demona) — wzorzec bezpiecznego, odwracalnego killswitcha.
- Suricata inline IPS (NFQUEUE, ~1–5 ms; AF_PACKET IPS wymaga par NIC) — research potwierdza flagę `bypass` (fail-open przy padzie demona), ale tryb inline **odrzucony decyzją #1** (pasywny IDS, killswitch out-of-band).
- Warstwy wolniejsze: VLAN-kwarantanna na managed switchu, DHCP lease denial (zbyt wolne solo), ARP/DAI; API routerów (OPNsense/UniFi, 50–200 ms) OK dla kwarantanny długoterminowej, nie dla reakcji real-time.
- Wymogi bezpieczeństwa z researchu: composite signals przed blokadą, TTL z auto-expiry, allowlista urządzeń krytycznych, pełny audit-log z możliwością przeglądu/cofnięcia.
- Unikać: komercyjne NDR (Darktrace itp.) — overkill; czysta DHCP-kwarantanna — za wolna.

**→ Decyzje:** #1, #12, #13 (progowy human-in-the-loop; DNS-sinkhole + ARP-isolation + switch ACL/port; fail-open + audyt — kroki 68–75, 90).

## Domena 8 — IaC i orkiestracja (Terraform/OpenTofu, bpg/proxmox, Ansible, k3s, Podman Quadlets, ArgoCD)

- Research rekomendował **OpenTofu** (MPL 2.0, graduacja CNCF IV 2025, szyfrowanie state od 1.7+) z powodu ryzyka licencyjnego BSL Terraforma → **decyzja: Terraform**; provider `bpg/proxmox` (v0.101.0+, jedyny żywy — Telmate stalled) działa z oboma, więc ewentualna migracja jest tania.
- **k3s** = standard homelab (dojrzały, ogromna społeczność); Talos Linux (immutable, API-only, bez SSH) — opcja przy multi-node w przyszłości; k0s/Nomad/Crossplane v2.0 — odrzucone (mniejszy ekosystem / overkill).
- **Podman Quadlets** (systemd-native, rootless, bez demona) = bleeding-edge następca docker-compose dla 1–3 usług — idealny profil edge na Pi.
- **ArgoCD** (graduacja CNCF) z app-of-apps + ApplicationSets do generowania profili; FluxCD — alternatywa przy budowie IDP, nie nasz przypadek.
- Ansible `community.proxmox` do konfiguracji day-2 po IaC.

**→ Decyzje:** #19–#22 (k3s+ArgoCD na serwerze, Podman Quadlets na Pi, Terraform+Ansible, ApplicationSet pi-edge/proxmox-soc — kroki 26–37).

## Domena 9 — DevSecOps pipeline i supply chain (skanery, SBOM, signing, SLSA, polityki)

- **Trivy skompromitowane (III 2026):** oficjalne repozytorium przejęte dwukrotnie w ciągu dwóch tygodni (skoordynowany atak) — niebezpieczne w zautomatyzowanym CI/CD. Zamienniki: **OSV-Scanner v2.3.5** (III 2026; skan tranzytywny przez deps.dev, guided remediation) + **Grype** (skan obrazów).
- **Automerge w Renovate/Dependabot = amplifikacja malware:** złośliwy Axios 1.7.7 zainstalowany w 895+ publicznych repo przez Dependabot → automerge OFF, wymagany review, `reachability-analysis: true`.
- **Harden-Runner** (monitoring egress; wykrył kompromitację `tj-actions/changed-files` CVE-2025-30066 i atak Sha1-Hulud w CNCF Backstage) + **pinowanie wszystkich akcji do SHA commita**.
- Sekrety: **gitleaks** (pre-commit + CI, szybki) + **TruffleHog** nightly z weryfikacją (klonuje do temp — mitygacja CVE-2025-41390 złośliwego git config).
- SAST: **Semgrep + CodeQL**; IaC: **Checkov + KICS** (+ kubeconform/kube-linter dla manifestów); Dockerfile: hadolint.
- Supply chain: **Syft → CycloneDX SBOM**, **cosign keyless** (Sigstore OIDC; Rekor v2 GA 2025 — attestacje przechowuje się przy artefaktach), **SLSA L2** (GitHub Artifact Attestations v2.0 GA / slsa-github-generator).
- Admission: **Kyverno 1.17** (II 2026, silnik CEL promowany do v1) — prostszy niż OPA Gatekeeper (v3.22) dla naszych polityk.
- Kontekst regulacyjny: EO 14028 + CISA minimum elements, EU CRA, NIS2 — SBOM staje się wymogiem prawnym; dobre dla projektu-wizytówki.
- Cele pipeline: <24 h MTTR dla critical, 100% pokrycia SAST/SCA, zero sekretów w repo, podpisane+atestowane artefakty.

**→ Decyzje:** #21, #25, #26 + „dodatkowe ustalenia" w `02-decisions.md`; kroki 14–25, 140.

## Domena 10 — Storage i observability (ClickHouse, Vector/Fluent Bit, Grafana/Alloy, gotowe platformy)

- **ClickHouse**: ~10× kompresja vs Elasticsearch; ClickStack (2025) unifikuje logi/metryki/trace'y w jednej bazie (≈90% redukcji storage vs silosy ELK); natywny tiering do S3/MinIO (cold) — idealny pod budżet 8 GB i retencję 30 dni hot. x86-only → Pi nie hostuje, tylko wysyła.
- **Pipeline logów: Fluent Bit (edge, <10 MB RAM) → Vector (serwer; VRL — enrichment i fan-out w Ruście, bez JVM Logstasha) → ClickHouse + Loki.**
- **Grafana Alloy zastępuje Promtail (EOL 2026)** — jeden agent na metryki+logi+trace'y+profile; Grafana v11+ (continuous profiling, lepszy backend OTel) jako warstwa wizualizacji.
- InfluxDB v3 / TimescaleDB / OpenSearch — odrzucone (silosy lub słabszy fit do OLAP na zdarzeniach sieciowych).
- Gotowe platformy: **SELKS 10** (VI 2024; PostgreSQL, conditional PCAP 10–100× mniej storage), **Security Onion 2.4.170** (I 2025; Zeek 7.0.9+Suricata 7.0.11+Elastic w OVA), **CISA Malcolm** — research traktował je jako mocny fundament, ale **decyzja #2 wybiera hybrydę z własną warstwą** (patrz Rozbieżności).
- ntopng→ClickHouse integration (2025) ułatwia długoterminowe baseliny behawioralne.

**→ Decyzje:** #15, #18, #28 (ClickHouse + Fluent Bit/Vector + pełny stack Prometheus/Grafana/Loki/Alloy/OTel — kroki 38–40, 61–63, 119–120).

---

## Synteza

### Build vs Assemble vs Appliance

Werdykt researchu: **ASSEMBLE** — nie czysty build from scratch (8–12 tygodni dodatkowej pracy: tuning reguł Suricaty, indeksowanie Arkime, operowanie ELK), nie czyste pudełko (SELKS/Security Onion: limit retencji ~90 dni, brak RITA/flow-anomalii, słaba integracja z własnym DevSecOps, lock-in). Research proponował konkretnie „SELKS 10 + rozszerzenia (ClickHouse, Grafana, Wazuh, AdGuard)"; **finalna decyzja przesuwa suwak dalej w stronę „build":** te same dojrzałe silniki (Suricata/Zeek/ntopng/AdGuard/RITA), ale składane samodzielnie + własna warstwa korelacji/killswitch/UI i własny pipeline — bo projekt jest portfolio/nauką i to własna platforma jest wizytówką (patrz `00-overview.md`). Argumentacja researchu „dlaczego nie czysty build / nie czyste pudełko" pozostaje w mocy.

### Rekomendowany stack (13 warstw — skrót; pełne uzasadnienia w surowym wyniku)

| Warstwa | Rekomendacja researchu | Status w decyzjach |
|---|---|---|
| Tap | SPAN na managed switchu + tc mirred; AF_XDP „za 2–3 lata" | ✅ przyjęte (AF_PACKET teraz, XDP w Fazie 3) |
| DPI/flow | Suricata + Zeek (+ntopng lekki L7) | ✅ przyjęte |
| DNS | AdGuard Home (nie Pi-hole v6) | ✅ przyjęte |
| Inwentaryzacja | DHCP opt55/60 + Fingerbank local + mDNS/ARP | ✅ przyjęte |
| IoC/enrichment | MISP + ThreatFox/GreyNoise/Spamhaus; Suricata dataset context | ✅ przyjęte |
| Anomalie | RITA v5.1 (ClickHouse) + Isolation Forest; ML głębokie opcjonalnie | ✅ przyjęte |
| Killswitch | XDP_DROP / nftables dynamic sets (TTL, fail-open) | ⚠️ zmodyfikowane: out-of-band (DNS/ARP/switch), nie inline |
| IaC/orkiestracja | OpenTofu + bpg/proxmox; k3s; Podman Quadlets na edge | ⚠️ Terraform zamiast OpenTofu; reszta przyjęta |
| CI/supply chain | GH Actions + Harden-Runner + OSV/Grype + gitleaks + Semgrep | ✅ przyjęte (+CodeQL, Checkov/KICS) |
| Storage | ClickHouse (+S3 cold) | ✅ przyjęte |
| Wizualizacja | Grafana v11+ | ✅ przyjęte (+własny frontend SvelteKit) |
| Appliance alternatywne | SELKS 10 / Security Onion | ❌ odrzucone (hybryda własna) |
| Signing | cosign keyless + Syft SBOM + SLSA L2 | ✅ przyjęte |

### Ryzyka zidentyfikowane w researchu (12)

1. **Ślepota ECH** (~50% klientów do 2026, brak SNI) → strategia DNS-first + JA4 już teraz.
2. **False-positive killswitch** (zablokowanie legalnego ruchu, np. Windows Update) → composite signals, wysokie progi, TTL auto-expiry, human-in-the-loop.
3. **Supply-chain w CI/CD** (Trivy III 2026, Codecov, XZ Utils) → pin-to-SHA, Harden-Runner, OSV zamiast Trivy, weryfikacja podpisów reguł.
4. **Prywatność/regulacje** (nawet w domu: RODO, IoT zdrowotne) → metadane-only, retencja z auto-expiry, JA4 pseudonimowe, polityka spisana i zakomunikowana domownikom.
5. **Alert fatigue** → agresywny tuning (suppress), alerty tylko composite, cotygodniowy przegląd reguł z FP >1%.
6. **Proxmox = SPOF** → watchdogi systemd, UPS, Pi jako zapasowy DNS; świadomość: to defense-in-depth, nie jedyna kontrola.
7. **Wąskie gardło Pi** (drop >20% przy nasyceniu CPU) → profil edge/minimal, pomiar drop-rate, baseline wydajności (krok 99).
8. **Luki driverów NIC dla XDP** (RTL8111 itd.) → AF_PACKET jako default, XDP tylko na serwerze z odpowiednim NIC.
9. **Narzut Wazuh** (manager 3 GB+ RAM) → odroczony do Fazy 3 / sprzętu 32 GB+ (krok 154).
10. **Blind spot DHCP** (statyczne IP) → p0f + ARP-rekonsyliacja + ręczna allowlista.
11. **Pełzanie kosztów** → start na darmowych feedach/ET Open, rozszerzenia dopiero po wykazanej potrzebie.
12. **Złożoność k3s** dla pojedynczego operatora → świadomie zaakceptowana (projekt-wizytówka DevSecOps); profil edge zostaje na prostszym Podmanie.

---

## Rozbieżności: rekomendacje researchu → decyzje finalne

Research był prowadzony „na zielono" (bez znajomości zastanego sprzętu i preferencji); wywiad decyzyjny świadomie zmienił część rekomendacji:

| # | Research rekomendował | Decyzja finalna | Powód |
|---|---|---|---|
| 1 | Raspberry Pi 5 / mini-PC N100 (16 GB) | **Pi 3B+ (1 GB) + istniejący serwer Proxmox ~8 GB/4 vCPU** | sprzęt zastany; stąd profile `pi-edge`/`proxmox-soc` i pisanie pod 4–8 GB |
| 2 | SELKS 10 jako fundament (assemble-and-extend) | **hybryda: silniki OSS + własna warstwa korelacji/killswitch/UI** | portfolio/nauka — własna platforma i DevSecOps są wizytówką; bez lock-inu pudełka |
| 3 | Wazuh manager jako hub SIEM/orkiestracji | **własne usługi Go; Wazuh opcjonalnie w Fazie 3 (32 GB+)** | 3 GB+ RAM nie mieści się w budżecie 8 GB; duplikuje własną warstwę |
| 4 | OpenTofu (BSL-risk Terraforma) | **Terraform** | provider `bpg/proxmox` działa z oboma; migracja tania, jeśli zajdzie potrzeba |
| 5 | Killswitch inline (XDP_DROP / NFQUEUE / nftables na ścieżce) | **pasywny IDS + killswitch out-of-band (DNS-sinkhole, ARP-isolation, switch ACL)** | sensor nie może położyć sieci domowej (fail-open by design); decyzja #1 |
| 6 | Pi jako transparent bridge w torze ruchu | **SPAN/port-mirror z managed switcha (pasywny tap)** | brak ingerencji w ścieżkę pakietów; prostszy failure mode |
| 7 | Home Assistant + Node-RED jako UI/orkiestracja | **własny `web-ui` (SvelteKit) + `killswitch-controller` (Go)** | pełna kontrola nad approvalem human-in-the-loop; mniejszy stack |
| 8 | pfSense/OPNsense API jako punkt egzekucji | **AdGuard API + ARP + managed switch** | router ISP jest zamknięty (brak API); decyzje #5/#13 |
| 9 | Elasticsearch/Kibana w części strumieni | **ClickHouse + Grafana** | 10× efektywność storage, jeden backend, budżet 8 GB |

## Fakty z researchu zakotwiczone w innych dokumentach (szybkie referencje)

- **Trivy: kompromitacja repo III 2026 (2× w 2 tyg.)** → `02-decisions.md` „NIE Trivy"; OSV-Scanner + Grype.
- **Axios 1.7.7 przez Dependabot automerge → 895+ repo** → automerge OFF (decyzja + krok 23).
- **Promtail EOL 2026 → Grafana Alloy** → krok 39.
- **RITA v5.1 z backendem ClickHouse (V 2026)** → krok 111.
- **MISP v2.5.37+ (IV 2026) natywny atrybut Suricata** → kroki 52, 56.
- **Suricata 8 dataset/datajson context** → krok 103.
- **JA4 zamiast JA3; ECH RFC 9849 ~50% do 2026** → decyzja #9, kroki 106, 110.
- **FP composite 0,01–0,1% vs pojedynczy sygnał 2–15%** → progi killswitcha (decyzja #12, kroki 116–117).
