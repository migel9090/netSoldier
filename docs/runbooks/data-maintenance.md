# Data Maintenance Runbook

## Data retention summary

Since step 119 the append-only time-series tables are tiered (storage
policy `tiered`): parts stay on the local hot disk for the "Hot" window,
then move to the S3 `cold` volume (in-cluster MinIO, bucket
`netsoldier-cold`, prefix `native/`), and are deleted at the "Delete"
horizon. Queries read both tiers transparently.

| Table | Hot (local) | Delete | Engine | Notes |
|-------|------------|--------|--------|-------|
| `devices` | forever | never | ReplacingMergeTree | Persistent device registry; not tiered |
| `device_events` | 30 days | 365 days | MergeTree | Tiered |
| `network_flows` | 30 days | 365 days | MergeTree | Tiered |
| `dns_queries` | 30 days | 365 days | MergeTree | Tiered |
| `connections` | 30 days | 365 days | MergeTree | Tiered |
| `alerts` | 90 days | 365 days | ReplacingMergeTree | Tiered |
| `events` | 90 days | 365 days | MergeTree | Tiered |
| `audit_log` | 180 days | 730 days | MergeTree | Tiered; do not truncate |
| `suricata_alerts` | 90 days | 365 days | MergeTree | Tiered; Suricata IDS alerts (EVE) |
| `suricata_dns` | 30 days | 365 days | MergeTree | Tiered |
| `suricata_tls` | 30 days | 365 days | MergeTree | Tiered; TLS handshakes (JA3) |
| `zeek_conn` | 30 days | 365 days | MergeTree | Tiered |
| `zeek_dns` | 30 days | 365 days | MergeTree | Tiered |
| `zeek_ssl` | 30 days | 365 days | MergeTree | Tiered |
| `zeek_x509` | 30 days | 365 days | MergeTree | Tiered |
| `zeek_http` | 30 days | 365 days | MergeTree | Tiered |
| `zeek_intel` | 30 days | 365 days | MergeTree | Tiered; Intel framework hits |
| `ml_beacons` | 30 days | 30 days | ReplacingMergeTree | State table, not tiered (Parquet export only) |
| `ml_anomalies` | 30 days | 30 days | ReplacingMergeTree | State table, not tiered (Parquet export only) |
| `detection_feedback` | 365 days | 365 days | ReplacingMergeTree | State table, not tiered |

ClickHouse enforces TTL automatically during merges and background moves.
No manual cleanup is needed under normal operation. Inserts never touch
S3 (`perform_ttl_move_on_insert=false`): if MinIO is down, ingest
continues hot-only and moves catch up later.

---

## DM-1: Check ClickHouse disk usage

```bash
# Overall disk usage
kubectl exec -n netsoldier clickhouse-0 -- df -h /var/lib/clickhouse

# Per-table disk usage
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "SELECT table,
          formatReadableSize(sum(bytes_on_disk)) AS size,
          sum(rows) AS rows
   FROM system.parts
   WHERE database = 'netsoldier' AND active
   GROUP BY table
   ORDER BY sum(bytes_on_disk) DESC
   FORMAT PrettyCompact"
```

**Healthy state:** Total usage well below the 20Gi PVC. TTL keeps tables
pruned automatically.

---

## DM-2: Force TTL cleanup (if disk is near full)

ClickHouse applies TTL during background merges. To force immediate cleanup:

```bash
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "OPTIMIZE TABLE netsoldier.network_flows FINAL"

kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "OPTIMIZE TABLE netsoldier.dns_queries FINAL"

kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "OPTIMIZE TABLE netsoldier.connections FINAL"
```

This triggers immediate merge + TTL evaluation. May take several minutes on
large tables.

---

## DM-3: Manual data deletion (emergency)

Use only when TTL cleanup is insufficient and the disk is critically full.

```bash
# Delete data older than N days from a specific table
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "ALTER TABLE netsoldier.network_flows
   DELETE WHERE timestamp < now() - INTERVAL 7 DAY"

# Wait for mutation to complete
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "SELECT * FROM system.mutations
   WHERE database = 'netsoldier' AND NOT is_done
   FORMAT PrettyCompact"
```

**Never delete from `audit_log`** — it is the compliance record for killswitch
actions.

---

## DM-4: Clear device inventory (SQLite)

The device-inventory SQLite database uses `emptyDir` storage. Restarting the
pod clears all discovered devices:

```bash
# Kubernetes
kubectl delete pod -n netsoldier -l app.kubernetes.io/name=device-inventory

# Podman
systemctl restart device-inventory.service
```

Devices reappear as they broadcast DHCP, mDNS, SSDP, or ARP packets. Full
re-discovery takes minutes depending on network activity.

To remove a single device without restarting, there is currently no delete API.
The device will age out of the list once its `last_seen` timestamp becomes
stale.

---

## DM-5: Verify backups

### Run the restore test

```bash
# Locally (with port-forward to ClickHouse and backup PVC mounted)
S3_ENDPOINT=http://localhost:9000 \
S3_BUCKET=netsoldier-backup \
S3_ACCESS_KEY=<key> \
S3_SECRET_KEY=<secret> \
CH_HOST=localhost \
BACKUP_DIR=/path/to/backup/pvc \
bash scripts/backup-restore-test.sh
```

### Or use the Taskfile target

```bash
task backup:test-restore
```

### Manual check — ClickHouse backup in S3

```bash
# List today's backup objects (via MinIO client)
mc ls minio/netsoldier-backup/clickhouse/$(date +%Y-%m-%d)/

# Expected output: schema.csv + one .native.zst file per non-empty table
```

### Manual check — state backup on PVC

```bash
# List backup directories
kubectl exec -n netsoldier <any-pod-with-pvc> -- ls -la /backup/state/

# Check latest backup contents
kubectl exec -n netsoldier <pod> -- ls -la /backup/state/$(date +%Y-%m-%d)/
# Expected: devices.json, configmaps.json, secrets.age
```

---

## DM-6: Restore ClickHouse from backup

**Full restore procedure** (after data loss or migration):

```bash
# 1. Download schema from S3
clickhouse-client --host <ch-host> --query \
  "SELECT create_table_query FROM s3(
    'http://minio:9000/netsoldier-backup/clickhouse/<date>/schema.csv',
    '<key>', '<secret>', 'CSVWithNames'
  ) FORMAT TabSeparatedRaw" > schema.sql

# 2. Recreate the database
clickhouse-client --host <ch-host> --query "CREATE DATABASE IF NOT EXISTS netsoldier"

# 3. Execute each CREATE TABLE statement from schema.sql
#    (edit the file to run each statement individually)

# 4. Restore data for each table
TABLES="devices device_events network_flows dns_queries alerts events connections audit_log"
for TABLE in $TABLES; do
  echo "Restoring $TABLE..."
  clickhouse-client --host <ch-host> --query \
    "INSERT INTO netsoldier.${TABLE}
     SELECT * FROM s3(
       'http://minio:9000/netsoldier-backup/clickhouse/<date>/${TABLE}.native.zst',
       '<key>', '<secret>', 'Native'
     )" 2>/dev/null && echo "  OK" || echo "  SKIP (no backup file)"
done
```

---

## DM-7: Restore device inventory from backup

The state backup stores the device list as JSON from the API:

```bash
# Download the backup
kubectl cp netsoldier/<backup-pod>:/backup/state/<date>/devices.json ./devices.json

# Verify contents
jq length devices.json
```

To reimport, use the device-inventory `PUT /devices/{mac}/labels` endpoint to
restore labels. The device records themselves are re-created automatically via
passive discovery — the backup preserves labeling and identification data.

---

## DM-8: Restore encrypted secrets

Requires the age private key (stored offline, never in the cluster):

```bash
# Decrypt the secrets backup
age -d -i /path/to/age-private-key.txt \
  -o secrets-decrypted.json \
  /backup/state/<date>/secrets.age

# Review the contents before applying
jq '.items[].metadata.name' secrets-decrypted.json

# Re-create secrets in the cluster
kubectl apply -f secrets-decrypted.json

# Securely delete the decrypted file
shred -u secrets-decrypted.json
```

---

## DM-9: Cold tier verification

There are two cold paths (step 119), both landing in the MinIO bucket
`netsoldier-cold` (namespace `storage`):

1. **Native tiering** (`native/` prefix): the `tiered` storage policy moves
   parts older than the hot window to the S3 disk. Data stays queryable
   through the normal tables.
2. **Parquet archive** (`cold/` prefix): the cold-export CronJob runs daily
   at 02:00 UTC and writes yesterday's rows as open-format Parquet — this
   copy survives a total ClickHouse loss.

```bash
# Native tier: rows per disk (expect old parts on s3_cold)
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "SELECT table, disk_name, sum(rows) AS rows
   FROM system.parts
   WHERE database = 'netsoldier' AND active
   GROUP BY table, disk_name
   ORDER BY table FORMAT PrettyCompact"

# Failed background moves surface here (e.g. MinIO down / missing creds)
kubectl logs -n netsoldier clickhouse-0 | grep -i "MergeTreePartsMover\|s3_cold" | tail

# Historical query smoke test (reads from the cold volume once data ages out)
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "SELECT count() FROM netsoldier.network_flows
   WHERE timestamp < now() - INTERVAL 30 DAY"

# Parquet archive: check recent job history
kubectl get jobs -n netsoldier -l app.kubernetes.io/component=cold-export \
  --sort-by=.metadata.creationTimestamp

# Verify yesterday's export exists
YESTERDAY=$(date -d yesterday +%Y-%m-%d)
mc ls minio/netsoldier-cold/cold/network_flows/year=${YESTERDAY:0:4}/month=${YESTERDAY:5:2}/day=${YESTERDAY:8:2}/

# Query the Parquet archive directly (works even without ClickHouse state)
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client --query \
  "SELECT count() FROM s3('http://minio.storage.svc:9000/netsoldier-cold/cold/network_flows/year=*/month=*/day=*/network_flows.parquet',
   '<S3_ACCESS_KEY>', '<S3_SECRET_KEY>', 'Parquet')"
```

**Applying migration 018 to an existing instance:** the init ConfigMap only
runs on first boot. On an already-initialized server, apply it manually:

```bash
kubectl exec -n netsoldier clickhouse-0 -- clickhouse-client \
  --multiquery < deploy/clickhouse/migrations/018_cold_tier.sql
```

---

## DM-10: Log rotation

### Kubernetes

Container logs are managed by the container runtime (containerd/CRI-O).
Configure log rotation in `/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  max_container_log_line_size = 16384

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
    max_log_size = "50m"
    max_log_files = 3
```

### Podman (Pi)

Podman logs are managed by journald. Configure retention in
`/etc/systemd/journald.conf`:

```ini
[Journal]
SystemMaxUse=500M
MaxRetentionSec=30day
```

Apply: `sudo systemctl restart systemd-journald`
