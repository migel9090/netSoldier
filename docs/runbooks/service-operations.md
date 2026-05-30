# Service Operations Runbook

## Service inventory

| Service | K8s Type | Namespace | Port | Health | Podman Unit |
|---------|----------|-----------|------|--------|-------------|
| detection-engine | Deployment | netsoldier | 8080 | `/healthz` | `detection-engine.service` |
| device-inventory | Deployment | netsoldier | 8081 | `/healthz` | `device-inventory.service` |
| killswitch-controller | Deployment | netsoldier | 8084 | `/healthz` | — |
| threat-intel-sync | Deployment | netsoldier | 8083 | `/healthz` | — |
| web-ui | Deployment | netsoldier | 3000 | `/` | `web-ui.service` |
| clickhouse | StatefulSet | netsoldier | 8123/9000 | `/ping` | — |
| adguard | StatefulSet | dns | 3000 | `/` | `adguard.service` |
| misp-core | StatefulSet | netsoldier | 8080 | `/users/login` | — |
| fluent-bit | DaemonSet | netsoldier | 2020 | `/api/v1/health` | `fluent-bit.service` |

---

## SO-1: Health checks

### Kubernetes

```bash
# Quick status of all pods
kubectl get pods -n netsoldier -o wide
kubectl get pods -n dns -o wide

# Probe a specific service
kubectl exec -n netsoldier deploy/detection-engine -- \
  wget -qO- http://localhost:8080/healthz

# Check pod events (crash loops, OOM kills, scheduling failures)
kubectl describe pod -n netsoldier <pod-name>

# Check resource usage
kubectl top pods -n netsoldier
```

### Podman (Pi)

```bash
# Check all containers
podman ps -a

# Health check each service
for port in 8080 8081 8082; do
  echo -n "localhost:$port — "
  curl -sf http://localhost:$port/healthz && echo "OK" || echo "DOWN"
done

# AdGuard
curl -sf http://localhost:3000/control/status && echo "AdGuard OK"
```

---

## SO-2: Restart a service

### Kubernetes — rolling restart (zero-downtime for Deployments)

```bash
# Deployment (detection-engine, device-inventory, killswitch, threat-intel, web-ui)
kubectl rollout restart deployment/<name> -n netsoldier

# StatefulSet (clickhouse, misp)
kubectl rollout restart statefulset/<name> -n netsoldier

# AdGuard (dns namespace)
kubectl rollout restart statefulset/adguard -n dns

# DaemonSet (fluent-bit) — restarts on ALL nodes
kubectl rollout restart daemonset/fluent-bit -n netsoldier

# Watch rollout progress
kubectl rollout status deployment/<name> -n netsoldier
```

### Kubernetes — force restart a stuck pod

```bash
# Delete the pod; the controller creates a new one
kubectl delete pod <pod-name> -n netsoldier

# If pod is stuck terminating (> 30s)
kubectl delete pod <pod-name> -n netsoldier --grace-period=0 --force
```

### Podman (Pi)

```bash
systemctl restart detection-engine.service
systemctl restart device-inventory.service
systemctl restart adguard.service
systemctl restart web-ui.service
systemctl restart fluent-bit.service

# Check status after restart
systemctl status <service>.service
```

---

## SO-3: Service not starting (CrashLoopBackOff)

**Symptoms:** Pod status shows `CrashLoopBackOff` or `Error`. Restart count
is climbing.

```bash
# Check why the container exited
kubectl logs -n netsoldier <pod-name> --previous

# Check events for OOM, image pull, or scheduling issues
kubectl describe pod -n netsoldier <pod-name>
```

**Common causes:**

| Symptom in logs | Cause | Fix |
|-----------------|-------|-----|
| `connection refused` to ClickHouse | ClickHouse not ready yet | Wait for CH startup (up to 2 min); check CH pod |
| `connection refused` to AdGuard | AdGuard not ready | Check AdGuard pod in `dns` namespace |
| `bind: address already in use` | Port conflict (hostNetwork) | Check for conflicting process: `ss -tlnp \| grep <port>` |
| `OOMKilled` | Container hit memory limit | Increase resource limits in deployment manifest |
| `permission denied` on `/data` | UID mismatch on PV | Check `fsGroup` in pod securityContext |
| `failed to pull image` | Registry auth / tag missing | Verify image exists: `docker pull <image>` |

---

## SO-4: ClickHouse not accepting connections

```bash
# Check pod status
kubectl get pods -n netsoldier -l app.kubernetes.io/component=server

# Check ClickHouse server logs
kubectl logs -n netsoldier clickhouse-0

# Test connectivity from within the cluster
kubectl run -n netsoldier --rm -it debug --image=alpine -- \
  wget -qO- http://clickhouse.netsoldier.svc:8123/ping
```

**If ClickHouse is in startup (up to 2 min):** Wait. The startup probe allows
120 seconds (5s interval × 24 failures).

**If ClickHouse is OOM-killed:** Check `kubectl describe pod clickhouse-0`.
The default memory limit is 2Gi. ClickHouse is configured to use 50% of
container memory. If the workload grew, increase the limit.

**If the PVC is full:**
```bash
kubectl exec -n netsoldier clickhouse-0 -- \
  df -h /var/lib/clickhouse
```
See [Data Maintenance](data-maintenance.md) for cleanup procedures.

---

## SO-5: AdGuard Home not resolving DNS

**Impact:** All DNS clients fail to resolve. Detection engine polling also
fails.

```bash
# Check pod in dns namespace
kubectl get pods -n dns
kubectl logs -n dns adguard-0

# Test DNS resolution through AdGuard
kubectl run -n dns --rm -it debug --image=alpine -- \
  nslookup example.com adguard-home.dns.svc

# On Pi
dig example.com @localhost
```

**If AdGuard pod is down:** Restart it. DNS clients will use the secondary
DNS server configured on the router (if any) as fallback.

```bash
kubectl rollout restart statefulset/adguard -n dns
```

**If AdGuard config is corrupted:**
```bash
# The config PVC holds AdGuardHome.yaml
kubectl exec -n dns adguard-0 -- cat /opt/adguardhome/conf/AdGuardHome.yaml
```

---

## SO-6: MISP core not starting

MISP has the longest startup time (up to 5 minutes). The startup probe allows
300 seconds.

```bash
# Check pod
kubectl get pods -n netsoldier -l app.kubernetes.io/component=core
kubectl logs -n netsoldier misp-core-0

# Check MariaDB is ready (MISP depends on it)
kubectl logs -n netsoldier misp-mariadb-0
kubectl exec -n netsoldier misp-mariadb-0 -- \
  healthcheck.sh --connect
```

**If MISP is stuck in init:** It may be running database migrations. Check
logs for migration output. Do not restart during migration.

**If MariaDB is down:** MISP cannot start. Fix MariaDB first:
```bash
kubectl rollout restart statefulset/misp-mariadb -n netsoldier
```

---

## SO-7: Fluent-bit not forwarding logs

```bash
# Check DaemonSet status
kubectl get pods -n netsoldier -l app.kubernetes.io/name=fluent-bit

# Check for output errors
kubectl logs -n netsoldier -l app.kubernetes.io/name=fluent-bit --tail=30

# Check metrics
kubectl exec -n netsoldier <fluent-bit-pod> -- \
  wget -qO- http://localhost:2020/api/v1/metrics
```

**If Vector (observability namespace) is down:** Fluent-bit buffers in memory
but will drop logs if the buffer fills. Restart Vector:
```bash
kubectl rollout restart deployment/vector -n observability
```

**If fluent-bit is OOM-killed:** The memory limit is 128Mi. Heavy log volume
(e.g. during a scan) can exceed this. Increase the limit or reduce input
rate.

---

## SO-8: Web UI shows "Failed to load" errors

The web UI proxies API calls to detection-engine and device-inventory. If
either backend is down, the corresponding section shows an error.

```bash
# Check which backend is down
curl -sf http://detection-engine.netsoldier.svc:8080/healthz
curl -sf http://device-inventory.netsoldier.svc:8081/healthz

# Check web-ui pod logs for proxy errors
kubectl logs -n netsoldier deploy/web-ui --tail=20
```

Fix the failing backend service (SO-2, SO-3). The web UI recovers
automatically once the backend is healthy (polls every 30 seconds).

---

## SO-9: Backup CronJobs failing

```bash
# Check recent job history
kubectl get jobs -n netsoldier -l app.kubernetes.io/name=backup --sort-by=.metadata.creationTimestamp

# Check failed job logs
kubectl logs -n netsoldier job/<job-name>

# Manual trigger (for testing)
kubectl create job backup-clickhouse-manual --from=cronjob/backup-clickhouse -n netsoldier
kubectl create job backup-state-manual --from=cronjob/backup-state -n netsoldier
```

**ClickHouse backup fails:** Check S3/MinIO connectivity. If `backup-s3`
secret is missing, the job skips gracefully (exit 0).

**State backup fails:** Check that the `backup-state` PVC is not full
(`kubectl exec` into a debug pod with the PVC mounted and run `df -h`).
