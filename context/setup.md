# SETUP — prompt onboardingowy dla Claude Code (projekt Argus)

> Wklej całą treść tego pliku jako **pierwszy prompt** po uruchomieniu Claude Code w katalogu tego repozytorium. Plik przygotuje agenta tak, by był „gotowy do pracy" — z pełnym kontekstem, odtworzoną pamięcią i znajomością wszystkich decyzji.

---

Jesteś Claude Code i przejmujesz projekt **Argus** — domowy system monitoringu ruchu sieciowego z detekcją zagrożeń, killswitchem i naciskiem na **bleeding-edge DevSecOps** (to priorytet-wizytówka). Repo jest **greenfield** (puste poza katalogiem `context/`). Twoim zadaniem jest doprowadzić projekt do **production-grade** według gotowej, 173-krokowej roadmapy.

## Krok 1 — Wczytaj kontekst (przeczytaj w tej kolejności)
Przeczytaj WSZYSTKIE pliki w `context/` zanim cokolwiek zaproponujesz:
1. `context/00-overview.md` — cel, zakres, filozofia.
2. `context/01-environment-and-constraints.md` — sprzęt (Raspberry Pi 3B+ jako edge/test; serwer Proxmox ~8GB/4vCPU jako docelowy), sieć, topologia, twarde ograniczenia.
3. `context/02-decisions.md` — 28 zatwierdzonych decyzji architektonicznych (NIE podważaj ich bez pytania użytkownika).
4. `context/03-architecture.md` — architektura, diagram, stack, struktura repo, pipeline DevSecOps.
5. `context/04-roadmap.md` — pełna roadmapa: 173 kroki (0–172), audyt co ~25 kroków (25, 50, 75, 100, 125, 150, 172). **To jest plan pracy.**
6. `context/05-research-findings.md` — wyniki researchu bleeding-edge 2024–2026 uzasadniające wybory technologii.

## Krok 2 — Odtwórz pamięć (memory)
Pamięć Claude Code jest lokalna dla maszyny (`~/.claude/projects/<slug-repo>/memory/`) i NIE przeniosła się z poprzedniej maszyny. Odtwórz ją:
- Utwórz w katalogu memory pliki: `project-argus.md` (typ: project), `roadmap-argus.md` (typ: project), `roadmap-format-preference.md` (typ: feedback), oraz `MEMORY.md` (indeks z 3 wskaźnikami).
- Treść skopiuj/streszczaj z: `02-decisions.md` + `00-overview.md` → `project-argus.md`; `04-roadmap.md` → `roadmap-argus.md`; sekcja „Preferencja formatu roadmap" poniżej → `roadmap-format-preference.md`.
- Format każdego wpisu: frontmatter `--- name / description / metadata.type ---`, w treści fakt + (dla project/feedback) linie `**Why:**` i `**How to apply:**`, linkowanie `[[nazwa]]`.

**Preferencja formatu roadmap (zapisz jako feedback):** gdy użytkownik prosi o roadmapę/plan krokowy — ma być granularna (≥150 kroków), każdy krok zaindeksowany od 0, ≤2 zdania na krok (złożone do maks 10 zdań), sanity-check/audyt co ~25 kroków, a wynik zapisany do pamięci.

## Krok 3 — Przyjmij sposób pracy (tak działałem ja)
- **DevSecOps-first.** Najpierw fundament (repo, CI/CD, security-gate, IaC, k3s+ArgoCD, observability) + cienki pionowy plaster end-to-end, dopiero potem warstwy funkcjonalne. Faza 0 → 1 → 2 → 3 z `04-roadmap.md`.
- **Realizuj kroki sekwencyjnie** wg roadmapy. Na każdym audycie (25/50/75/100/125/150/172) zatrzymaj się, zweryfikuj kryteria i zapisz wynik w `docs/audits/`.
- **Pytaj, gdy decyzja należy do użytkownika** lub gdy działanie jest trudne do cofnięcia/wychodzi na zewnątrz (push, deploy, publikacja, killswitch na żywej sieci). Domyślnie nie commituj/pushuj bez prośby.
- **Multi-arch (amd64+arm64)** od początku; profile `pi-edge` i `proxmox-soc` przez overlaye Kustomize.
- **Bezpieczeństwo łańcucha dostaw**: akcje pinowane do SHA, Harden-Runner, OSV-Scanner+Grype (NIE Trivy — patrz `05-research-findings.md`), SBOM (Syft/CycloneDX), cosign keyless + SLSA L2, automerge wyłączony, Kyverno verifyImages.
- **Killswitch zawsze progowy / human-in-the-loop**, z allowlistą (fail-open) i pełnym audytem; egzekucja DNS-sinkhole + ARP-isolation + ACL/port na managed switchu. Bez MITM (tylko metadane: JA4/JA3+SNI+DNS).
- **Prywatność**: brak inspekcji payloadu; retencja domyślnie 30 dni.

## Krok 4 — Potwierdź środowisko
Zapytaj/potwierdź u użytkownika: czy pracujemy na Pi 3B+ (profil edge, throttling OK) czy na serwerze Proxmox (profil SOC), oraz czy managed switch jest już podłączony (SPAN). Dostosuj profil i ograniczenia zasobów (na 8GB pilnuj requests/limits; ciężkie DPI/ML/ClickHouse tylko `proxmox-soc`).

## Krok 5 — Zacznij
Po wczytaniu kontekstu, odtworzeniu pamięci i potwierdzeniu środowiska: przedstaw krótkie podsumowanie „co zrozumiałem + od czego zaczynam", a następnie **poczekaj na zielone światło** użytkownika i rozpocznij od **kroku 0** (inicjalizacja monorepo + fundament DevSecOps). Nie wykonuj kroków zmieniających system, dopóki użytkownik nie potwierdzi.

## Szybka ściąga decyzji (pełna lista w `02-decisions.md`)
Pasywny IDS + killswitch out-of-band • hybryda (gotowe silniki + własna warstwa) • DNS=AdGuard Home • DPI=Suricata+Zeek+ntopng • TLS metadane-only (JA4/JA3+SNI) • anomalie=RITA + Isolation Forest • threat-intel=abuse.ch/GreyNoise/Spamhaus→MISP • storage=ClickHouse • język=Go(+Python ML) • UI=Grafana+frontend SvelteKit • alerty=webhook • k3s+ArgoCD (cel) / Podman na Pi • IaC=Terraform+Ansible • CI=GitHub Actions • sekrety=SOPS+age • monorepo • admission=Kyverno • gate CI=blok critical/high • testy detekcji=replay PCAP w CI • observability=Prometheus+Grafana+Loki+Alloy+OTel.

## Guardrails
To autoryzowany monitoring **własnej** sieci domowej za zgodą domowników (kontekst defensywny/edukacyjny). Funkcje ofensywne (ARP-isolation, killswitch) służą wyłącznie ochronie własnej sieci i muszą pozostać pod kontrolą człowieka (zatwierdzanie, allowlista, audyt, fail-open).
