# context/ — pakiet startowy projektu netSoldier

Ten katalog zawiera **kompletny kontekst** potrzebny, by Claude Code (lub człowiek) zaczął pracę nad projektem **netSoldier** (domowy monitoring ruchu sieciowego + detekcja zagrożeń + killswitch + pełny DevSecOps) na dowolnej maszynie.

## Jak użyć (na nowej maszynie)
1. Skopiuj cały katalog repo (z `context/`) na docelową maszynę.
2. Uruchom Claude Code w katalogu repo.
3. Wklej/wskaż treść **`setup.md`** jako pierwszy prompt — to instrukcja onboardingowa, która oprowadzi agenta po tym katalogu, każe wczytać kontekst i odtworzyć pamięć, po czym przygotuje go do pracy od kroku 0 roadmapy.

## Zawartość
| Plik | Co zawiera |
|---|---|
| `setup.md` | **Prompt onboardingowy dla Claude Code** — czytaj/wklej jako pierwszy. |
| `00-overview.md` | Cel projektu, zakres, filozofia. |
| `01-environment-and-constraints.md` | Sprzęt (Pi 3B+, serwer Proxmox), sieć, topologia, ograniczenia. |
| `02-decisions.md` | Wszystkie decyzje z 7-rundowego wywiadu technicznego (28 rozstrzygnięć). |
| `03-architecture.md` | Architektura, diagram, stack technologiczny, struktura repo, pipeline DevSecOps. |
| `04-roadmap.md` | Pełna granularna roadmapa: 173 kroki (0–172), audyt co ~25. |
| `05-research-findings.md` | Wyniki researchu bleeding-edge 2024–2026 (10 domen + synteza). |
| `research-raw.json` | Surowy output researchu (~358 KB, workflow `wf_74fc0ed0-f1d`) — źródło destylacji `05`. |

## Status
Projekt jest **greenfield** — repo jest puste poza tym katalogiem `context/`. Implementacja jeszcze się nie zaczęła; pierwszy krok to **krok 0** z `04-roadmap.md`.
