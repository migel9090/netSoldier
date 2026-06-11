# Performance Baseline

Measured limits and expected performance for netSoldier on both deployment
profiles. Run `scripts/perf-baseline.sh` on each target to reproduce.

---

## Hardware profiles

| | Pi 3B+ (`pi-edge`) | Server (`proxmox-soc`) |
|---|---|---|
| CPU | 4× Cortex-A53 @ 1.4 GHz | 4+ vCPU (x86-64) |
| RAM | 1 GB | 8 GB |
| Disk | 32 GB µSD (class 10) | NVMe / SSD |
| Network | 1× Gbit Ethernet (USB 2.0 bus, ~300 Mbps effective) | 1+ Gbit Ethernet |
| Throttling | Yes — bcm2837 throttles at 80 °C; check `vcgencmd get_throttled` | No thermal throttling expected |

---

## Resource budget

### Pi 3B+ (`pi-edge`)

Total available: ~900 MB usable (kernel + OS ~100 MB). Services must fit
within ~600 MB including OS overhead.

| Service | CPU request | CPU limit | Mem request | Mem limit |
|---------|------------|-----------|-------------|-----------|
| detection-engine | 50m | 200m | 64 Mi | 128 Mi |
| device-inventory | 50m | 200m | 64 Mi | 128 Mi |
| fluent-bit | 10m | 50m | 24 Mi | 48 Mi |
| AdGuard Home | — | — | ~80 Mi | ~150 Mi |
| **Total** | **110m** | **450m** | **232 Mi** | **454 Mi** |

Headroom: ~150 MB for OS buffers and spikes. No ClickHouse, MISP, web-ui,
killswitch, or threat-intel on Pi.

### Server (`proxmox-soc`)

Total available: 8 GB. Full stack including ClickHouse and MISP.

| Service | CPU request | CPU limit | Mem request | Mem limit |
|---------|------------|-----------|-------------|-----------|
| detection-engine | 200m | 500m | 256 Mi | 512 Mi |
| device-inventory | 200m | 500m | 256 Mi | 512 Mi |
| killswitch-controller | 100m | 300m | 128 Mi | 256 Mi |
| threat-intel-sync | 100m | 300m | 128 Mi | 256 Mi |
| web-ui | 100m | 300m | 128 Mi | 256 Mi |
| ClickHouse | 250m | 1000m | — | 2048 Mi |
| fluent-bit | 25m | 100m | — | 128 Mi |
| MISP | — | — | ~512 Mi | ~1024 Mi |
| AdGuard Home | — | — | ~80 Mi | ~150 Mi |
| Suricata (incl. Vector + updater) | 600m | 2400m | 768 Mi | 1536 Mi |
| **Total** | **~1575m** | **~5400m** | **~2.25 Gi** | **~6.6 Gi** |

Headroom: ~1.4 GB for OS, Kubernetes control plane, and ClickHouse data
caches. Suricata is capped by explicit memcaps (flow 64mb, stream
64mb + reassembly 128mb with 1mb depth, defrag/host 16mb, datasets
64mb, http 64mb) and a trimmed ET Open ruleset (see
`suricata-updater-script` disable.conf), so its 1 Gi limit holds in
practice well below the configured ceiling.

---

## Expected throughput

### API endpoints (steady state, no load)

| Endpoint | Pi 3B+ | Server |
|----------|--------|--------|
| GET `/healthz` (any service) | > 500 rps | > 2000 rps |
| GET `/alerts` (empty) | > 300 rps | > 1500 rps |
| GET `/devices` (10 devices) | > 200 rps | > 1000 rps |
| POST `/evaluate` (ignore path) | > 100 rps | > 800 rps |
| POST `/evaluate` (pending/active) | > 50 rps | > 500 rps |

### Detection pipeline

| Metric | Pi 3B+ | Server |
|--------|--------|--------|
| AdGuard poll interval | 30s | 30s (configurable) |
| DNS entries processed per poll | up to 200 | up to 1000 |
| IoC matching (linear scan, 10k domains) | < 50 ms | < 10 ms |
| Alert → webhook delivery | < 200 ms | < 50 ms |

### Killswitch response time

| Metric | Pi 3B+ | Server |
|--------|--------|--------|
| Evaluate → decision latency | < 50 ms | < 10 ms |
| Approve → AdGuard rule applied | < 500 ms | < 200 ms |
| Auto-block → sinkhole active | < 500 ms | < 200 ms |
| Revert → rule removed | < 500 ms | < 200 ms |

---

## Known limits

### Pi 3B+

- **CPU throttling**: sustained load above 80 °C triggers ARM frequency
  scaling. With a passive heatsink, expect throttling during concurrent
  build+run. Active cooling (fan case) mitigates this.
- **µSD I/O**: random write throughput on class-10 µSD is ~5 MB/s. SQLite WAL
  flushes can stall under heavy device churn. Consider USB SSD for production.
- **Memory ceiling**: 128 Mi per service is tight. Detection-engine with a
  large threat list (>50k domains) may approach the limit. Monitor OOM kills.
- **No ClickHouse**: hot storage is unavailable on Pi. Detection-engine
  operates in webhook-only mode — no historical queries.
- **Single Ethernet**: all traffic (management + monitored network) shares one
  NIC. USB 2.0 bus limits effective throughput to ~300 Mbps regardless of
  Gbit PHY.

### Server (8 GB)

- **ClickHouse memory**: limited to 2 Gi. Complex analytical queries on large
  datasets (>10M rows) may OOM. Use `max_memory_usage` server setting to
  enforce per-query limits.
- **MISP startup**: up to 5 minutes on cold start (database migrations). The
  startup probe allows 300 seconds.
- **Concurrent scans**: a full network scan by device-inventory (ARP + mDNS +
  SSDP) on a /16 subnet generates ~65k packets. During discovery bursts,
  detection-engine CPU spikes to ~80% of its 500m limit.
- **IoC list size**: the in-memory domain set scales linearly. At 100k domains,
  expect ~50 MB RSS overhead in detection-engine. The 512 Mi limit supports up
  to ~500k domains.
- **ClickHouse disk**: 20 Gi PVC with 30-day TTL on flow tables. At ~1000
  flows/min average, expect ~10 GB/month of hot storage. Monitor via DM-1.

---

## Drop rate expectations

| Scenario | Pi 3B+ | Server |
|----------|--------|--------|
| Normal home traffic (<50 devices, <100 DNS/min) | 0% | 0% |
| Heavy traffic (50+ devices, 500 DNS/min) | < 1% | 0% |
| Burst (network scan, 1000+ DNS/min) | < 5% | 0% |
| Stress (sustained 5000 DNS/min) | 10-30% (CPU bound) | < 1% |

Drop = AdGuard querylog entries that cycle out of the log buffer before the
next poll interval. Reduce `POLL_INTERVAL` to mitigate, at the cost of higher
CPU usage.

---

## Benchmark methodology

### Running the benchmark

```bash
# On Pi (services running locally via Podman or K3s)
DURATION=30 CONCURRENCY=2 bash scripts/perf-baseline.sh

# On server (services running in K8s, port-forwarded)
kubectl port-forward -n netsoldier svc/detection-engine 8080:8080 &
kubectl port-forward -n netsoldier svc/device-inventory 8081:8081 &
kubectl port-forward -n netsoldier svc/killswitch-controller 8084:8084 &
DURATION=30 CONCURRENCY=4 bash scripts/perf-baseline.sh
```

### Interpreting results

The script outputs a JSON file with per-test metrics:

- **rps**: requests per second sustained over the duration
- **latency_ms**: min / avg / max response time
- **drop_rate_pct**: percentage of failed requests (timeouts + errors)
- **resources_snapshot**: RSS and CPU% of each service process at end of run

### Thermal monitoring (Pi)

```bash
# Check throttling during benchmark
vcgencmd get_throttled
# 0x0 = no throttling
# 0x50005 = currently throttled + under-voltage detected

# Live temperature
vcgencmd measure_temp
```

### Taskfile target

```bash
task perf:baseline
```

---

## Updating this document

After running `scripts/perf-baseline.sh` on a target, update the tables above
with measured values. Keep both the "expected" (theoretical) and "measured"
columns. The expected values serve as regression thresholds — if measured
performance drops below expected, investigate before shipping.
