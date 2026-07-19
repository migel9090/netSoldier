# detections/ — detection-as-code

| Path | Purpose | Lands at |
|---|---|---|
| `suricata/` | local rules + rulesets generated from threat-intel (`threat-intel-sync`) | steps 55, 102–103 |
| `zeek/` | Zeek scripts: TLS client fingerprint (JA4-format), Intel framework wiring | steps 105–107 |
| `pcap-corpus/` | **manifest-only** corpus (download manifests + checksums + expected-alert assertions) replayed in CI as detection regression tests | steps 89, 123–124 |

Raw `*.pcap`/`*.pcapng` files are **never committed** (root `.gitignore`); CI fetches
them from the manifest (malware-traffic-analysis et al.) into an ephemeral workspace.
Every rule/script change must keep the corpus replay green.
