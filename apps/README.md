# apps/ — netSoldier services

Each service is self-contained: own multi-stage Dockerfile (distroless, non-root),
multi-arch build (amd64+arm64), `/healthz` + `/metrics` (Prometheus) endpoints,
OpenTelemetry instrumentation.

| Service | Lang | Role | Lands at |
|---|---|---|---|
| `detection-engine/` | Go | consumes Suricata EVE / Zeek / ntopng; correlation "who→where→what"; IoC matching; composite confidence; events → ClickHouse | step 9 (skeleton), 43, 64–67, 109–116 |
| `device-inventory/` | Go | DHCP opt 55/60 + mDNS/SSDP/LLDP + ARP/OUI + Fingerbank (local); MAC-randomization-resistant identity → SQLite/ClickHouse | steps 42, 57–60 |
| `killswitch-controller/` | Go | threshold policy, allowlist (fail-open), pending/approve/revert lifecycle, append-only audit; drivers: DNS-sinkhole, ARP-isolation, managed-switch | steps 68–74 |
| `threat-intel-sync/` | Go | MISP + abuse.ch/GreyNoise/Spamhaus feeds → AdGuard lists, Suricata datasets, Zeek Intel | steps 52–55 |
| `ml-anomaly/` | Python | RITA glue (C2 beaconing) + Isolation Forest (volumetric); FastAPI scoring | steps 8 (init), 112–115 |
| `web-ui/` | SvelteKit | device map, alerts, killswitch approval screen | steps 8 (init), 45, 74, 76–78, 130–131 |
