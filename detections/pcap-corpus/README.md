# PCAP corpus — detection regression tests

One capture per malware/C2 traffic family, replayed through **the production
Suricata rules and Zeek scripts** on every change. If a rule edit stops
catching beaconing, or a script change drops `tls_client_fp`, this fails.

```bash
./gen_corpus.py            # rebuild the captures (deterministic)
./test/verify.py           # replay through both sensors and assert (needs docker)
./test/verify.py --report  # print what the sensors actually produced
./download.sh --list       # real-world captures available on demand
```

## What is in it

| Family | Capture | Exercises |
|---|---|---|
| HTTP C2 beacon | `c2-http-beacon` | fixed-interval callbacks (RITA beaconing), `http.host` IoC rule |
| TLS C2 beacon | `c2-tls-beacon` | SNI IoC rule, implant TLS fingerprint |
| Direct-to-IP C2 | `ioc-ip-contact` | IoC-IP rule, SNI-less + DNS-less TLS heuristics |
| DGA rendezvous | `dns-dga` | high-entropy DNS, mostly NXDOMAIN |
| DNS tunnelling | `dns-tunnel-exfil` | long encoded labels, TXT reply channel |
| Port sweep | `scan-portsweep` | S0 connection fan-out |
| Benign control | `benign-baseline` | must produce **zero** alerts |

The benign capture is not filler. A corpus containing only malicious traffic
cannot catch a rule that alerts on everything, so every run asserts an upper
bound of zero alerts on ordinary browsing.

## Why the captures are generated, not recorded

They have to replay in CI on every PR, which rules out fetching from a third
party at test time, and `*.pcap` is gitignored repo-wide. So `gen_corpus.py`
builds them from raw bytes — no scapy, no capture files in git. It is
deterministic (fixed timestamps, SHA-256-derived variation instead of an RNG),
so the `sha256` pins in `manifest.yaml` double as a reproducibility gate:
if a generator change is not byte-reproducible, verification fails.

Addressing uses only RFC 5737 documentation ranges and RFC 2606 reserved
domains, so nothing in the corpus can be mistaken for a real host or C2.

## Real-world captures

`manifest.yaml` also pins four captures from
[malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)
(© Brad Duncan, shared for research and education) covering a RAT chain,
infostealer exfiltration over FTP, a Linux coinminer, and a week of internet
background scanning. They are **optional** — CI never touches them — and exist
for deep local validation and purple-team work (step 126).

`download.sh` fetches and checksum-verifies the archives but deliberately does
not unpack them: the archive password is published only as an image on the
source site, which is the author's way of refusing scripted extraction.
Extract by hand when you need them, and keep the results out of the repo.

## Adding a family

1. Write a `gen_*` function in `gen_corpus.py` and register it in `FAMILIES`.
2. `./gen_corpus.py` — note the printed packet count and sha256.
3. `./test/verify.py --report` — see what Suricata and Zeek actually produce.
4. Add the entry to `manifest.yaml` with those values under `expect`.
5. `./test/verify.py` — must pass.

Expectations are deliberately asymmetric: `suricata.sids` and `zeek.min_lines`
are lower bounds (a sensor upgrade that finds *more* should not break the
build), while `packets`, `sha256` and `suricata.max_alerts` are exact, because
those are the things a regression would quietly change.

## A documented gap

`dns-tunnel-exfil` asserts **no** Suricata alert. The dataset rules match the
full query name exactly, so data tunnelled through subdomains of a known-bad
zone slips past them, while detection-engine's matcher — which walks parent
domains — catches it. That asymmetry is pinned here on purpose so that closing
it (steps 127–128) shows up as a deliberate expectation change rather than a
surprise.
