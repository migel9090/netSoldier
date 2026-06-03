# 04 — Roadmapa: 173 kroki do production-grade (0–172)

**To jest plan pracy projektu Argus.** Kroki realizuj sekwencyjnie; na każdym audycie (**25, 50, 75, 100, 125, 150, 172**) zatrzymaj się, zweryfikuj kryteria i spisz wynik w `docs/audits/`. Kopia robocza tej roadmapy żyje też w pamięci Claude Code (`memory/roadmap-argus.md`) — przy zmianach aktualizuj oba miejsca.

Mapa faz:
- **Faza 0 (0–50):** fundament DevSecOps + cienki pionowy plaster. Audyty: 25, 50.
- **Faza 1 (51–100):** pełny lekki MVP funkcjonalny. Audyty: 75, 100.
- **Faza 2 (101–150):** ciężka analiza na serwerze + production-readiness. Audyty: 125, 150.
- **Faza 3 (151–172):** hardening i rozbudowa → `v1.0.0`. Audyt: 172.

## FAZA 0 — Fundament DevSecOps + cienki pionowy plaster

0. Utwórz monorepo `netSoldier`, zainicjalizuj git, dodaj `.gitignore`, `LICENSE`, `README.md` ze szkicem celu projektu.
1. Ustal konwencje: Conventional Commits, SemVer, model trunk-based z krótkimi feature-branchami i obowiązkowym PR review.
2. Stwórz strukturę katalogów wg planu (`apps/`, `deploy/`, `infra/`, `detections/`, `observability/`, `security/`, `docs/`, `.github/`).
3. Dodaj `docs/adr/0001-architektura.md` z decyzjami z wywiadu; załóż katalog na kolejne ADR.
4. Napisz `docs/threat-model.md` (STRIDE) dla systemu monitoringu + killswitcha.
5. Skonfiguruj `.editorconfig`, `.gitattributes` i formattery (gofmt/goimports, ruff/black, prettier).
6. Dodaj `.pre-commit-config.yaml`: gitleaks, semgrep, checkov, hadolint, formattery; udokumentuj w `docs/dev-setup.md`.
7. Zainicjalizuj moduł Go (`go.mod`) i workspace dla usług w `apps/`.
8. Zainicjalizuj projekt Python (`apps/ml-anomaly`, `pyproject.toml`) i frontend (`apps/web-ui`, SvelteKit + pnpm).
9. Napisz minimalną usługę Go „healthz" (szkielet `apps/detection-engine`) z `/healthz` i `/metrics` (Prometheus).
10. Dodaj `Dockerfile` (multi-stage, distroless/nonroot) dla usługi Go; zweryfikuj lokalny build.
11. Skonfiguruj `docker buildx` do obrazów multi-arch (amd64+arm64); przetestuj build arm64 lokalnie.
12. Załóż repo na GitHub, ustaw branch protection (wymagany PR review, status checks, brak force-push do main).
13. Skonfiguruj GHCR jako registry; ustaw uprawnienia i `packages: write` w workflow.
14. Dodaj `.github/workflows/ci.yml` szkielet: lint + test + build (Harden-Runner, akcje pinowane do SHA).
15. Dodaj job SAST: Semgrep + CodeQL (Go/Python/JS) z uploadem SARIF do GitHub Security.
16. Dodaj job SCA: OSV-Scanner + Grype (świadomie zamiast Trivy); progi blokowania critical/high.
17. Dodaj job IaC-scan: Checkov + KICS (na razie no-op, gotowe pod `infra/`).
18. Dodaj job secret-scan: gitleaks w CI + zaplanuj nightly TruffleHog (verify).
19. Dodaj generowanie SBOM: Syft → CycloneDX jako artefakt buildu.
20. Dodaj podpisywanie obrazów: cosign keyless (Sigstore/OIDC) po pushu do GHCR.
21. Dodaj provenance SLSA L2 (slsa-github-generator) dla obrazów i artefaktów.
22. Skonfiguruj self-hosted arm64 runner (Pi lub QEMU) do buildów/testów arm64; udokumentuj rejestrację.
23. Skonfiguruj Renovate/Dependabot z automerge WYŁĄCZONYM i wymaganym review.
24. Dodaj `Taskfile`/`Makefile` z celami: build, test, lint, scan, sbom, sign, up, deploy.
25. **[AUDIT #1]** Sanity check fundamentu CI: PR z podsadzonym sekretem MUSI być zablokowany przez gitleaks; obraz multi-arch w GHCR ma podpis cosign + SBOM + provenance SLSA; wszystkie gate'y zielone na czystym PR. Zweryfikuj pinowanie akcji do SHA i raport egress z Harden-Runner. Spisz wyniki w `docs/audits/audit-01.md`.
26. `infra/terraform`: provider `bpg/proxmox`, backend state (lokalny/MinIO), zmienne i `terraform.tfvars.example`.
27. Terraform: definicja VM pod k3s na Proxmoksie (CPU/RAM/dysk, cloud-init, sieć/bridge).
28. Terraform: zasoby sieciowe/storage + outputy (IP, kubeconfig); `terraform validate` + `plan` w CI (read-only).
29. `infra/ansible`: inwentarz (Pi + serwer) i role bootstrap OS (Debian/Ubuntu serwer; Raspberry Pi OS 64-bit na Pi).
30. Ansible role hardening: nftables/ufw, fail2ban, unattended-upgrades, SSH hardening, użytkownik nie-root, CIS-lite.
31. Ansible: instalacja k3s na serwerze (wyłączony traefik/servicelb), kubeconfig do artefaktu.
32. Ansible: instalacja Podman + Quadlets na Pi (profil edge) na tych samych obrazach.
33. Zainstaluj ArgoCD na k3s; skonfiguruj dostęp (ingress/port-forward), zmień domyślne hasło → SOPS.
34. Skonfiguruj SOPS + age (klucz, `.sops.yaml`, szyfrowanie sekretów w `deploy/`); integracja z ArgoCD (ksops/sops-operator).
35. Zainstaluj Kyverno; polityki: tylko podpisane obrazy (verifyImages cosign), non-root, readOnlyRootFS, wymagane limits.
36. Utwórz `deploy/helm/argus` (umbrella chart) + `deploy/kustomize/base` i overlaye `pi-edge` / `proxmox-soc`.
37. Skonfiguruj ArgoCD app-of-apps + ApplicationSet generujący profile `pi-edge` i `proxmox-soc`.
38. Wdróż observability core: kube-prometheus-stack (Prometheus + Grafana + Alertmanager) przez ArgoCD.
39. Dodaj Loki + Grafana Alloy (zamiast Promtail) do logów; podłącz źródła.
40. Dodaj OpenTelemetry Collector + instrumentację OTel w usłudze Go (traces → Collector/Tempo).
41. Wdróż AdGuard Home (konfiguracja jako kod); ustaw jako resolver i przetestuj na jednym kliencie.
42. Rozszerz `device-inventory` (Go): nasłuch DHCP (opcja 55/60) → SQLite; API `/devices`.
43. Dodaj do `detection-engine` jedną detekcję: match domeny z listy ThreatFox (statyczna na start) na logach AdGuard.
44. Dodaj wysyłkę alertu przez generyczny webhook (konfigurowalny URL, payload JSON, retry/backoff).
45. Dodaj minimalny `web-ui` (SvelteKit): lista urządzeń + lista alertów (czyta API usług).
46. Połącz pionowy plaster end-to-end na serwerze (k3s/ArgoCD) i na Pi (Podman); ten sam obraz, różne overlaye.
47. Napisz test e2e plastra: zapytanie o „złą" domenę → sinkhole + alert webhook + wpis widoczny w UI.
48. Dodaj dashboard Grafany „System Health" (as-code) dla usług plastra + reguły alertów Prometheus.
49. Udokumentuj „getting started" + diagram architektury plastra w `docs/`.
50. **[AUDIT #2]** Sanity check Fazy 0: pełna ścieżka commit→CI(skan+SBOM+podpis+SLSA)→GHCR→ArgoCD sync→działający plaster na obu profilach; Kyverno odrzuca niepodpisany obraz (test negatywny). Zweryfikuj observability (metryki+log+trace) i alert webhook. Spisz w `docs/audits/audit-02.md`; zamknij Fazę 0.

## FAZA 1 — Pełny lekki MVP funkcjonalny

51. AdGuard: per-client config (mapowanie urządzeń), upstream DoH/DoT, logowanie zapytań dla pipeline.
52. `threat-intel-sync` (Go): klient MISP (REST) — pobieranie atrybutów (domeny/IP/JA3/hash).
53. `threat-intel-sync`: integracja abuse.ch ThreatFox + URLhaus + Feodo (API/CSV) z cache i deduplikacją.
54. `threat-intel-sync`: integracja GreyNoise Community (reputacja IP) + listy Spamhaus DROP/EDROP.
55. `threat-intel-sync`: eksport IoC do (a) list AdGuard, (b) reguł/datasetów Suricata, (c) Zeek Intel framework.
56. Wdróż MISP jako kontener (profil serwera) z bazą i schedulerem feedów; sekrety przez SOPS.
57. `device-inventory`: mDNS/SSDP/LLDP discovery do wzbogacania nazw urządzeń.
58. `device-inventory`: pasywny/aktywny ARP + lookup OUI (baza producentów) do klasyfikacji.
59. `device-inventory`: Fingerbank (tryb lokalny) do profilowania OS/modelu; obsługa randomizacji MAC (korelacja opt60+hostname).
60. `device-inventory`: model danych urządzenia (stabilne ID, etykiety, first/last seen) → ClickHouse + SQLite cache.
61. Wdróż ClickHouse (serwer) + schema dla flow/eventów/alertów; migracje jako kod.
62. Skonfiguruj Fluent Bit na Pi → wysyłka EVE/DNS/inventory do serwera (Vector/ClickHouse).
63. Skonfiguruj Vector na serwerze: ingest + enrichment (geo/ASN, reverse-DNS) + fan-out do ClickHouse i Loki.
64. `detection-engine`: capture AF_PACKET fanout (gopacket) na interfejsie SPAN; ekstrakcja flowów (5-tuple, bytes, czas).
65. `detection-engine`: korelacja flow + DNS + inventory → rekord „kto→gdzie→czym" do ClickHouse.
66. `detection-engine`: rozbuduj detekcje IoC (domeny/IP/JA3/JA4) z `threat-intel-sync`; tagowanie severity + MITRE ATT&CK.
67. Zdefiniuj kontrakt zdarzenia detekcji (schema, wersjonowanie) współdzielony przez usługi.
68. `killswitch-controller` (Go): model polityki progowej (confidence/severity/źródło) + allowlist krytycznych (fail-open).
69. `killswitch-controller`: stany akcji (pending/approved/active/reverted) + append-only audit log → ClickHouse.
70. `killswitch-controller`: sterownik „DNS-sinkhole" (AdGuard API) — najszybsza, bezpieczna blokada.
71. `killswitch-controller`: sterownik „ARP-isolation" (izolacja L2) z zabezpieczeniami i auto-revert po TTL.
72. `killswitch-controller`: sterownik „managed-switch" (SNMP/REST/SSH) — disable portu / quarantine-VLAN dla urządzeń przewodowych.
73. `killswitch-controller`: API zatwierdzania/cofania akcji + uwierzytelnianie; idempotencja i bezpieczny revert.
74. `web-ui`: ekran zatwierdzania killswitcha (pending) z kontekstem detekcji i akcjami approve/reject/revert.
75. **[AUDIT #3]** Sanity check rdzenia detekcji+killswitch: end-to-end IoC match → akcja pending → approve → realna blokada (DNS/ARP/switch) → revert; allowlistowane urządzenie nigdy nie blokowane; audit log kompletny; testy progów i fail-open. Spisz w `docs/audits/audit-03.md`.
76. `web-ui`: „mapa urządzeń" (graf kto→gdzie) near-real-time z danych ClickHouse.
77. `web-ui`: szczegóły urządzenia (historia połączeń, DNS, alerty, fingerprint).
78. `web-ui`: widok alertów z filtrowaniem (severity, urządzenie, czas, źródło IoC).
79. Grafana: dashboard „Network Overview" (top talkers, protokoły, kraje/ASN) as-code.
80. Grafana: dashboard „DNS & Threat-Intel" (zapytania, sinkhole hits, trafienia IoC) as-code.
81. Grafana: dashboard „Killswitch & Audyt" (akcje, czas reakcji, FP rate) as-code.
82. Reguły alertów Prometheus/Grafana → webhook (krytyczny IoC, urządzenie offline, kolejka approvali).
83. Skonfiguruj retencję ClickHouse (TTL hot 30 dni) + przygotuj eksport cold do MinIO/S3 (konfigurowalne).
84. Profil `pi-edge`: ustal usługi na Pi (AdGuard, device-inventory, Fluent Bit, lekka detekcja) — feature-flagi w Helm values.
85. Profil `proxmox-soc`: pełen zestaw + ClickHouse + MISP + Grafana; resource requests/limits pod 8 GB.
86. Testy jednostkowe Go (≥70% krytycznych ścieżek) + testy Python ML; bramka pokrycia w CI.
87. Testy integracyjne: ephemeral ClickHouse + AdGuard w CI (testcontainers/compose).
88. Testy kontraktowe między usługami (schema zdarzeń) + testy API (killswitch, inventory).
89. Detection-as-code (start): `detections/pcap-corpus` (manifest pobierania) + test replay 1 PCAP w CI.
90. Testy bezpieczeństwa killswitcha: brak możliwości blokady allowlisty, wymagana autoryzacja, działający auto-revert.
91. Hardening kontenerów: nonroot, readOnlyRootFS, seccomp/AppArmor, drop capabilities; zgodność z Kyverno.
92. NetworkPolicies (k8s) dla izolacji usług + least-privilege RBAC dla service accounts.
93. Liveness/readiness/startup probes + PodDisruptionBudgets + sensowne resource limits dla wszystkich usług.
94. Konfiguracja jako kod: configi usług w Git (Helm values) + walidacja schematu configów w CI.
95. Backup stanu: ClickHouse + SQLite + konfiguracje + sekrety (zaszyfrowane); harmonogram + test restore.
96. Dokumentacja użytkownika: dodawanie urządzenia, czytanie alertów, zatwierdzanie killswitcha (`docs/user-guide.md`).
97. Runbook operacyjny: typowe incydenty, restart usług, czyszczenie danych (`docs/runbooks/`).
98. Pełny e2e Fazy 1 na Pi i serwerze: inwentaryzacja, DNS, detekcja, killswitch, dashboardy, alerty.
99. Performance baseline na Pi 3B+ (throttling) i serwerze: throughput, drop-rate, CPU/RAM; udokumentuj limity.
100. **[AUDIT #4]** Sanity check MVP (Faza 1): kompletny przepływ na obu profilach; pełne pokrycie testami (unit/integration/contract/e2e/1×PCAP); dashboardy i alerty działają; killswitch bezpieczny; backup/restore zweryfikowany; baseline wydajności spisany; przegląd RBAC/NetworkPolicy/Kyverno. `docs/audits/audit-04.md`; zamknij Fazę 1.

## FAZA 2 — Ciężka analiza na serwerze

101. Wdróż Suricata 7/8 (serwer) w trybie AF_PACKET na SPAN; EVE JSON → Vector/ClickHouse.
102. Suricata: ruleset ET Open + auto-update (suricata-update) + lokalne reguły z `threat-intel-sync`.
103. Suricata: włącz „dataset/datajson context" — wzbogacanie alertów o metadane IoC (źródło/severity/ATT&CK).
104. Suricata: tuning (threads, AF_PACKET fanout, ring size) pod 8 GB; ogranicz ruleset jeśli ciasno.
105. Wdróż Zeek 8 (serwer): conn/dns/ssl/x509/http → pipeline.
106. Zeek: włącz JA4/JA4+ (i JA3) + JARM; eksport do ClickHouse.
107. Zeek: Intel framework zasilany z `threat-intel-sync` (domeny/IP/certy/JA-hashe).
108. Wdróż ntopng (serwer/edge wg zasobów) z nDPI; integracja flow do ClickHouse lub przez Vector.
109. `detection-engine`: konsumpcja EVE (Suricata) + logów Zeek + ntopng → ujednolicony model zdarzeń.
110. `detection-engine`: korelacja JA4/SNI/DNS → wykrywanie podejrzanych klientów TLS/QUIC bez deszyfracji.
111. Wdróż RITA v5.1 (backend ClickHouse) + zasilanie logami Zeek conn; harmonogram analiz.
112. `ml-anomaly` (Python): integracja wyników RITA (beaconing C2 score) → zdarzenia detekcji z confidence.
113. `ml-anomaly`: Isolation Forest na cechach flow (bytes/duration/dst-fanout) → detekcja exfil/wolumetrii.
114. `ml-anomaly`: pipeline treningu/ewaluacji (baseline z danych domowych), wersjonowanie modeli, metryki FP/FN.
115. `ml-anomaly`: serwowanie modeli (FastAPI) + endpoint scoringu; instrumentacja OTel + metryki.
116. `detection-engine`: composite-confidence — łączenie sygnałów (sygnatura + beaconing + wolumetria + JA4 + IoC).
117. `killswitch-controller`: progi oparte na composite-confidence (auto-block tylko high-confidence; reszta → approval).
118. Strojenie FP: pętla feedbacku z UI (oznacz FP) → korekta progów/allowlist; metryka FP rate na dashboardzie.
119. ClickHouse: warstwa cold (MinIO/S3) + polityki TTL/tiering; test zapytań historycznych.
120. Vector: rozbudowa enrichment (ASN, geo, threat-intel tagi, reverse-DNS) + routing per typ zdarzenia.
121. Grafana: dashboard „DPI & Protocols" (Suricata/Zeek/ntopng) + „TLS/JA4 anomalies" as-code.
122. Grafana: dashboard „Beaconing & Anomalies" (RITA/IsolationForest) z drill-down do urządzenia.
123. Rozszerz `detections/pcap-corpus`: wiele rodzin malware/C2 (malware-traffic-analysis + testy Suricata/Zeek).
124. Detection-as-code: pełny replay korpusu PCAP w CI z asercjami na alertach Suricata/Zeek + ścieżce killswitcha.
125. **[AUDIT #5]** Sanity check Fazy 2 (rdzeń analityczny): Suricata+Zeek+ntopng+RITA+IsolationForest produkują skorelowane, wzbogacone zdarzenia; composite-confidence steruje progami killswitcha; replay korpusu PCAP w CI przechodzi; FP rate akceptowalny; wydajność na 8 GB w normie (drop-rate, opóźnienia). `docs/audits/audit-05.md`.
126. Walidacja „purple-team": odtwórz scenariusze (C2 beacon, DGA, exfil, skan portów) i potwierdź wykrycie+reakcję.
127. Dodaj detekcję DGA (entropia/lexical domen DNS) w `ml-anomaly` lub `detection-engine`.
128. Dodaj detekcję skanów/lateral movement (Zeek + heurystyki) → zdarzenia z severity.
129. Dodaj korelację czasową/sesyjną (łączenie powiązanych alertów w „incydent") w `detection-engine`.
130. `web-ui`: widok „Incydenty" (zgrupowane alerty, timeline, dotknięte urządzenia, rekomendowana akcja).
131. `web-ui`: live „mapa kto→gdzie" z warstwą zagrożeń (kolorowanie wg severity/IoC) i filtrami.
132. Optymalizacja zapytań ClickHouse (ORDER BY/partycje/materialized views) pod dashboardy i historię.
133. Skalowanie pipeline: backpressure + kolejka (NATS/Redis Streams) między capture a detekcją jeśli potrzeba.
134. Hardening MISP + rotacja kluczy feedów (SOPS); monitoring świeżości IoC (alert gdy feed nieaktualny).
135. Testy chaosu (lekkie): zabij usługę/pod, odłącz ClickHouse — sprawdź degradację (fail-open killswitcha, brak utraty audytu).
136. Testy obciążeniowe: replay dużego PCAP/generator ruchu → max throughput serwera i punkt drop.
137. SLO/SLI: zdefiniuj (czas reakcji killswitcha, opóźnienie alertu, dostępność UI) + reguły alertów na naruszenia.
138. „Golden signals" w Grafanie dla każdej usługi (latency/traffic/errors/saturation) z OTel/Prometheus.
139. Audyt zależności i licencji: SBOM diff w CI + raport licencji (OSS compliance) w `docs/`.
140. Pełny przegląd supply-chain: weryfikacja podpisów+provenance przy deployu (Kyverno verifyImages) + test odrzucenia niepodpisanego.
141. Pen-test wewnętrzny: próba obejścia killswitch/allowlisty, podszycia pod IoC source, nadużycia API — załataj.
142. Privacy review: potwierdź metadane-only (brak payloadu), polityki retencji, maskowanie wrażliwych pól.
143. Dokumentacja architektury „as-built" + zaktualizowane ADR + diagramy C4 w `docs/`.
144. Runbooki incident-response per scenariusz (C2, exfil, nowe urządzenie, false-positive) w `docs/runbooks/`.
145. DR plan: backup (Velero dla k8s + restic dla danych) + udokumentowany i przetestowany restore na czysty serwer.
146. Release management: tagowanie wersji, changelog (release-please), obrazy wersjonowane i niezmienne.
147. Strategia wdrożeń: ArgoCD sync waves + health checks + automatyczny rollback przy błędzie.
148. Smoke testy po deployu (post-sync hooks) sprawdzające kluczowe ścieżki end-to-end po każdym rollout.
149. „Production readiness checklist" (`docs/prod-readiness.md`) wypełniony dla obu profili.
150. **[AUDIT #6]** Sanity check production-readiness: SLO spełnione; chaos+load przetestowane; DR restore działa; supply-chain w pełni egzekwowany (signed+SLSA+Kyverno); pen-test/privacy review zamknięte; rollback/smoke działają; dokumentacja kompletna. `docs/audits/audit-06.md`; zatwierdź gotowość „production grade".

## FAZA 3 — Hardening i rozbudowa

151. Wdróż capture eBPF/XDP na serwerze (zamiennik/uzupełnienie AF_PACKET) dla niższego narzutu CPU; benchmark vs AF_PACKET.
152. Przygotuj integrację dedykowanego AP za switchem (pełne DPI WiFi): dokumentacja topologii + overlay konfiguracji.
153. Po dołożeniu AP: przenieś WiFi za switch, włącz pełne DPI dla WiFi; zweryfikuj widoczność pakietową.
154. (Opcjonalnie, przy 32 GB+) wdróż Wazuh (HIDS) + integracja zdarzeń host-based z `detection-engine`.
155. (Opcjonalnie) wdróż Arkime (full PCAP, JA4) dla forensyki; conditional capture (PCAP tylko dla alertów).
156. Rozszerz threat-intel o STIX/TAXII (OpenCTI/MISP feeds) + automatyczny scoring źródeł.
157. Dodaj zaawansowaną korelację ML (autoencoder/Kitsune) jako opcjonalny moduł z ewaluacją FP.
158. Multi-sensor: kilka Pi/sensorów → jeden SOC (Fluent Bit → Vector), dedup po sensorze.
159. Dodaj uwierzytelnianie/SSO do UI i Grafany (OIDC) + RBAC ról (viewer/operator/admin).
160. Audyt dostępu do UI/API + logi bezpieczeństwa do Loki/ClickHouse z alertami.
161. Automatyzacja aktualizacji reguł (Suricata/Zeek/IoC) z testem regresji (replay PCAP) przed wdrożeniem.
162. Cost/perf tuning: profilowanie usług (pprof/py-spy), redukcja pamięci pod 8 GB, ewentualny HPA.
163. Canary/blue-green dla krytycznych usług (ArgoCD Rollouts) z automatyczną analizą metryk.
164. Polityki data-lifecycle (anonimizacja po X dni, twarde usuwanie) zgodne z privacy review.
165. Testy odtworzeniowe „from scratch": pełny bootstrap (Terraform+Ansible+ArgoCD) na czystym sprzęcie w <1 dzień, udokumentowany.
166. Wewnętrzny status page / healthboard dla stanu całego systemu.
167. Przegląd i automatyzacja rotacji wszystkich sekretów (age keys, API tokens, certy) + procedura.
168. Finalna dokumentacja: architektura, operacje, bezpieczeństwo, onboarding, ADR — kompletny `docs/`.
169. Niezależny przegląd kodu i bezpieczeństwa całego repo (np. `/code-review ultra` + security-review); załataj krytyczne.
170. Tag `v1.0.0` „production grade": wszystkie gate'y zielone, SLO spełnione, DR/rollback działają, dokumentacja i audyty kompletne.
171. Post-release monitoring (1–2 tygodnie): obserwuj SLO/FP rate/zasoby; zbierz feedback i utwórz backlog ulepszeń.
172. **[AUDIT #7 — FINAL]** Pełny audyt końcowy: powtórz skrótowo audyty 1–6, potwierdź brak regresji, zweryfikuj v1.0.0 w działaniu na obu profilach, zamknij threat-model (wszystkie ryzyka zaadresowane/zaakceptowane), podpisz production readiness. `docs/audits/audit-final.md`.
