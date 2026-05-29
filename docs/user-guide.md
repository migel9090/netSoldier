# User Guide

Day-to-day guide for operating a netSoldier deployment. Covers device
management, threat alerts, and killswitch approvals through the web dashboard.

For initial setup and deployment see [getting-started.md](getting-started.md).

## Accessing the Dashboard

Open the web UI in a browser:

| Profile     | Default URL                         |
|-------------|-------------------------------------|
| Proxmox SOC | `http://<server-ip>:3000`           |
| Pi edge     | `http://<pi-ip>:8082`               |
| Local dev   | `http://localhost:5173`              |

The sidebar links to each section: **Devices**, **Alerts**, **Killswitch**,
and **Network Map**.

---

## Devices

### How devices are discovered

netSoldier discovers devices passively — no scanning or probing required.
Five protocol listeners run simultaneously:

| Protocol | What it captures                        |
|----------|-----------------------------------------|
| DHCP     | MAC, IP, hostname, fingerprint, vendor class |
| mDNS     | hostname, service advertisements        |
| SSDP     | UPnP device descriptions                |
| LLDP     | switch-connected device identity        |
| ARP      | MAC-to-IP associations                  |

Devices appear automatically within seconds of joining the network. If
`ARP_SCAN_SUBNET` is configured, active ARP scans supplement passive
discovery.

### MAC randomization

Modern phones and laptops rotate their MAC address for privacy. netSoldier
handles this by computing a **Stable ID** from the device's DHCP vendor class
and hostname. Devices that share the same Stable ID are recognized as the same
physical device even when their MAC changes.

### Device list

Navigate to **Devices** in the sidebar. The table shows all discovered devices
ordered by most recently seen:

| Column           | Meaning                                        |
|------------------|------------------------------------------------|
| MAC              | Hardware address (link to device detail)        |
| IP               | Current IP address                              |
| Hostname         | Name from DHCP/mDNS                             |
| DHCP Fingerprint | DHCP option 55 parameter list (identifies OS)   |
| Vendor Class     | DHCP option 60 (device model hint)              |
| First Seen       | When the device was first observed               |
| Last Seen        | Most recent activity                             |

Click any MAC address to open the device detail page.

### Device detail

The detail page shows:

- **Identity cards** — MAC, IP, vendor (OUI lookup), OS, device type, DHCP
  fingerprint, first/last seen timestamps.
- **Labels** — user-assigned tags displayed as colored badges.
- **Alerts** — threat detections triggered by this device (last 50).
- **Connection History** — recent network connections: destination, port,
  protocol, bytes transferred, duration (last 100, from ClickHouse).
- **DNS Queries** — recent DNS lookups: domain, query type, answer, response
  time, whether the query was blocked (last 100, from ClickHouse).

### Labeling devices

Labels help you classify devices (e.g. `trusted`, `iot`, `guest`). To set
labels via the API:

```bash
curl -X PUT http://<device-inventory>:8081/devices/<mac>/labels \
  -H 'Content-Type: application/json' \
  -d '{"labels": ["trusted", "nas"]}'
```

Sending an empty array clears all labels:

```bash
curl -X PUT http://<device-inventory>:8081/devices/<mac>/labels \
  -H 'Content-Type: application/json' \
  -d '{"labels": []}'
```

Labels appear on the device detail page in the web UI.

---

## Alerts

### How alerts are generated

The detection engine polls AdGuard Home's query log every 30 seconds (configurable
via `POLL_INTERVAL`). Each DNS query is checked against the active threat
intelligence:

1. **Static threat list** — domains loaded from `domains.txt` at startup.
2. **Dynamic IoCs** — indicators synced from MISP via threat-intel-sync:
   domains, IPs, JA3/JA4 hashes, file hashes.

When a query matches an IoC, an alert is created with:

| Field       | Description                                      |
|-------------|--------------------------------------------------|
| Severity    | `critical`, `high`, `medium`, or `low`           |
| Confidence  | 0–100% — how certain the match is malicious      |
| Domain      | The queried domain                                |
| Client IP   | The device that made the query                    |
| Matched IoC | The specific indicator that triggered the alert   |
| Threat      | Malware family or threat classification           |
| MITRE       | ATT&CK technique ID when available                |
| Source      | Which threat feed provided the IoC                |

### Reading alerts

Navigate to **Alerts** in the sidebar. The page shows all recent alerts with
real-time updates (refreshes every 30 seconds).

**Filters** appear at the top of the page:

| Filter   | Options                                           |
|----------|---------------------------------------------------|
| Severity | Toggle buttons for `critical` / `high` / `medium` / `low` |
| Device   | Free-text filter by client IP address              |
| Source   | Dropdown of threat feed sources present in alerts  |
| Time     | Last 1h, 6h, 24h, 7d, or all time                 |

The filtered count shows next to the total (e.g. "12 / 47"). Click **Clear**
to reset all filters.

### What to do when you see an alert

1. **Check severity and confidence.** A critical alert at 95% confidence is
   almost certainly real. A medium alert at 55% may be a false positive.
2. **Click the client IP** to see the device detail page — check whether this
   is a known, trusted device.
3. **Review the domain** — is it a known-bad domain, or could it be a
   legitimate service that shares infrastructure with malicious actors?
4. **Check the MITRE ID** for context on the attack technique.
5. **Take action** — if the alert is genuine, head to the Killswitch page to
   block the threat. If it is a false positive, no action is needed.

### Webhook notifications

If `WEBHOOK_URL` is configured on the detection engine, alerts are also pushed
as HTTP POST requests in real time. Use this for integration with Slack,
PagerDuty, or other notification systems.

---

## Killswitch

The killswitch provides network-level enforcement: blocking compromised devices
at the DNS, ARP, or switch level. All enforcement actions follow a controlled
approval workflow.

### How enforcement works

When the detection engine generates an alert, the killswitch controller
evaluates it against the policy:

| Outcome       | Condition                                          | Result                |
|---------------|----------------------------------------------------|-----------------------|
| Auto-block    | Confidence >= 90% AND severity = critical          | Blocked immediately   |
| Pending       | Confidence >= 50% AND severity >= medium           | Requires approval     |
| Ignore        | Below thresholds, or device is allowlisted         | No action taken       |

The thresholds are configurable via environment variables on the killswitch
controller (`POLICY_AUTO_CONFIDENCE`, `POLICY_AUTO_SEVERITY`,
`POLICY_PENDING_CONFIDENCE`, `POLICY_PENDING_SEVERITY`).

### Action types

| Type           | Effect                                               |
|----------------|------------------------------------------------------|
| DNS Sinkhole   | Adds a blocking rule in AdGuard Home for the domain  |
| ARP Isolate    | Isolates the device via ARP spoofing (L2)            |
| Switch ACL     | Moves the device to a quarantine VLAN via webhook    |

The default action type is `dns_sinkhole`. This can be changed with the
`POLICY_DEFAULT_ACTION` environment variable.

### Pending approvals

Navigate to **Killswitch** in the sidebar. The **Pending Approvals** section
lists actions waiting for human review:

| Column     | Meaning                                            |
|------------|----------------------------------------------------|
| ID         | Action identifier (e.g. `ACT-42`)                  |
| Time       | When the detection triggered                        |
| Domain/IoC | The blocked domain or indicator                     |
| Target     | Device IP or MAC being blocked                      |
| Action     | Enforcement type (DNS Sinkhole, ARP Isolate, etc.)  |
| TTL        | How long the block lasts before auto-revert         |
| Reason     | Policy rule that triggered the action               |

For each pending action:

- **Approve** — confirms the block. A confirmation dialog appears. Once
  approved, the enforcement is applied immediately and the action moves to the
  Active Blocks section.
- **Reject** — dismisses the action. You will be prompted for a reason (e.g.
  "False positive"). The action is archived and the device is not blocked.

### Active blocks

The **Active Blocks** section shows currently enforced actions:

| Column      | Meaning                                           |
|-------------|---------------------------------------------------|
| ID          | Action identifier                                  |
| Since       | When the block was activated                        |
| Domain/IoC  | What is being blocked                               |
| Target      | The affected device                                 |
| Action      | Enforcement type                                    |
| Expires     | When the block auto-reverts (based on TTL)          |
| Approved by | Who approved (`auto-policy` for auto-blocks)        |

To remove a block before it expires, click **Revert** and enter a reason. The
enforcement is removed immediately and the action is archived.

### TTL and auto-revert

Every enforcement action has a time-to-live (default: 1 hour, configurable via
`POLICY_DEFAULT_TTL`). When the TTL expires, the block is automatically
reverted. This prevents forgotten blocks from permanently disrupting the
network.

The killswitch controller checks for expired actions every 10 seconds.

### Allowlist

Critical devices (router, NAS, servers) should be allowlisted to prevent
accidental blocking. Allowlisted devices are always ignored by the policy
engine regardless of alert severity.

Configure the allowlist via environment variables on the killswitch controller:

```bash
ALLOWLIST_MACS=aa:bb:cc:dd:ee:f0,aa:bb:cc:dd:ee:f1
ALLOWLIST_IPS=192.168.1.1,192.168.1.2
```

View the current allowlist:

```bash
curl -s http://<killswitch>:8084/allowlist | jq .
```

### Killswitch API reference

All POST endpoints require a Bearer token if `KILLSWITCH_API_KEY` is set:

```bash
curl -X POST http://<killswitch>:8084/actions/ACT-42/approve \
  -H 'Authorization: Bearer <your-api-key>' \
  -H 'Content-Type: application/json' \
  -d '{"approved_by": "admin"}'
```

| Method | Path                      | Description            |
|--------|---------------------------|------------------------|
| GET    | `/actions/pending`        | List pending actions   |
| GET    | `/actions/active`         | List active blocks     |
| GET    | `/actions/{id}`           | Get action detail      |
| POST   | `/actions/{id}/approve`   | Approve pending action |
| POST   | `/actions/{id}/reject`    | Reject pending action  |
| POST   | `/actions/{id}/revert`    | Revert active block    |
| GET    | `/allowlist`              | View allowlist         |
| GET    | `/policy`                 | View policy thresholds |

### State machine

Every enforcement action follows this lifecycle:

```
              ┌─── reject ──→ Rejected
              │
  Pending ────┤
              │
              └─── approve ──→ Approved ──→ Active ──→ Reverted
                                              │
                                   TTL expires or manual revert
```

All state transitions are recorded in the audit log (ClickHouse
`netsoldier.audit_log` table) for post-incident review.

---

## Network Map

Navigate to **Network Map** in the sidebar to see a topology visualization of
device-to-device connections. The map is built from ClickHouse flow data and
shows which devices communicate with each other, with edge thickness
representing traffic volume.

---

## Audit Log

Every killswitch state transition is recorded in ClickHouse for compliance
and incident review:

| Field        | Description                          |
|--------------|--------------------------------------|
| timestamp    | When the transition occurred         |
| action_id    | Enforcement action ID                |
| from_state   | Previous state                       |
| to_state     | New state                            |
| actor        | Who made the change                  |
| reason       | Why the change was made              |
| detection_id | Original alert reference             |
| target_mac   | Affected device MAC                  |
| target_ip    | Affected device IP                   |
| action_type  | Enforcement type                     |

Query the audit log directly:

```bash
clickhouse-client --host <clickhouse> --query \
  "SELECT * FROM netsoldier.audit_log ORDER BY timestamp DESC LIMIT 20"
```

Retention: 180 days.
