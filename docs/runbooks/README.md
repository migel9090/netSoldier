# Operational Runbooks

Procedures for common incidents, service operations, and data maintenance on
a netSoldier deployment.

| Runbook | When to use |
|---------|-------------|
| [Incident Response](incident-response.md) | Threat detected, device compromised, false-positive storm |
| [Service Operations](service-operations.md) | Health check, restart, scaling, connectivity issues |
| [Data Maintenance](data-maintenance.md) | Storage cleanup, backup verification, retention, migration |

## Quick reference

### Health check (all services)

```bash
# Kubernetes
for svc in detection-engine device-inventory killswitch-controller threat-intel-sync web-ui; do
  echo -n "$svc: "
  kubectl exec -n netsoldier deploy/$svc -- wget -qO- http://localhost:8080/healthz 2>/dev/null || echo "UNREACHABLE"
done

# Podman (Pi)
for port in 8080 8081 8084 8083; do
  echo -n "localhost:$port — "
  curl -sf http://localhost:$port/healthz || echo "DOWN"
done
```

### Emergency: revert all active killswitch blocks

```bash
# List active blocks
curl -s http://killswitch-controller.netsoldier.svc:8084/actions/active | jq '.[].id'

# Revert each (requires KILLSWITCH_API_KEY if set)
for id in $(curl -s http://killswitch-controller.netsoldier.svc:8084/actions/active | jq -r '.[].id'); do
  curl -X POST "http://killswitch-controller.netsoldier.svc:8084/actions/$id/revert" \
    -H 'Content-Type: application/json' \
    -d '{"reason": "emergency revert"}'
done
```
