# detections/ — detection-as-code

| Path | Purpose | Lands at |
|---|---|---|
| `suricata/` | local rules + rulesets generated from threat-intel (`threat-intel-sync`) | steps 55, 102–103 |
| `zeek/` | Zeek scripts: TLS client fingerprint (JA4-format), Intel framework wiring | steps 105–107 |
| `pcap-corpus/` | traffic corpus (one capture per malware/C2 family) + expected-alert assertions, replayed through Suricata and Zeek as detection regression tests — see its [README](pcap-corpus/README.md) | steps 89, 123–124 |

Raw `*.pcap`/`*.pcapng` files are **never committed** (root `.gitignore`). The corpus
captures are regenerated deterministically by `pcap-corpus/gen_corpus.py` and pinned by
checksum in the manifest; real-world captures (malware-traffic-analysis.net) are fetched
on demand by `pcap-corpus/download.sh` and are never required by CI.
Every rule/script change must keep the corpus replay green.
