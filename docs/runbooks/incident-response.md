# Incident Response Runbook

## IR-1: Threat alert — confirmed malicious domain

**Trigger:** Critical or high-severity alert on the Alerts page or via webhook.

**Steps:**

1. Open the alert in the web UI (**Alerts** page). Note the severity,
   confidence, domain, client IP, and MITRE technique ID.

2. Identify the device: click the client IP to open the device detail page.
   Check hostname, vendor, OS, and labels. Is this a known device?

3. Review the device's recent DNS queries and connections for lateral movement
   or data exfiltration patterns (unusual ports, high outbound volume, repeated
   queries to DGA-like domains).

4. If the threat is genuine and confidence is high:
   - Navigate to **Killswitch**. The detection engine will have already created
     a pending action (or auto-blocked if confidence >= 90% and severity =
     critical).
   - **Approve** the pending action if present. Choose the appropriate
     enforcement: DNS sinkhole is sufficient for a single bad domain; ARP
     isolate or switch ACL for a fully compromised device.

5. Investigate the IoC source: check the `source` field. If the IoC came from
   a public feed (abuse.ch, ThreatFox), cross-reference with the feed's page
   for context (malware family, campaign).

6. If the device is compromised beyond a single domain hit:
   - Escalate to IR-2 (compromised device procedure).
   - Consider isolating the device at the network switch level.

7. Document the incident: the killswitch audit log captures all enforcement
   state transitions automatically in ClickHouse (`netsoldier.audit_log`).

---

## IR-2: Compromised device

**Trigger:** Multiple high-severity alerts from a single device, unusual
outbound traffic patterns, or manual investigation revealing active C2.

**Steps:**

1. **Isolate immediately.** Use the killswitch to apply ARP isolation or switch
   ACL quarantine. If the killswitch controller is unavailable, manually block
   the device at your network switch or router.

2. **Preserve evidence.** Before wiping the device, capture:
   ```bash
   # Export device connections and DNS from ClickHouse
   clickhouse-client --host <ch-host> --query \
     "SELECT * FROM netsoldier.connections
      WHERE src_mac = '<device-mac>'
      ORDER BY timestamp DESC
      FORMAT CSVWithNames" > connections.csv

   clickhouse-client --host <ch-host> --query \
     "SELECT * FROM netsoldier.dns_queries
      WHERE client_ip = '<device-ip>'
      ORDER BY timestamp DESC
      FORMAT CSVWithNames" > dns_queries.csv

   # Export all alerts for the device
   clickhouse-client --host <ch-host> --query \
     "SELECT * FROM netsoldier.alerts
      WHERE client_ip = '<device-ip>'
      ORDER BY timestamp DESC
      FORMAT CSVWithNames" > alerts.csv
   ```

3. **Identify the attack vector.** Review the device's DNS queries for the
   initial C2 domain. Check when the first malicious query occurred. Look at
   connection history for data exfiltration (large outbound bytes to unknown
   IPs).

4. **Check for lateral movement.** Query ClickHouse for connections FROM the
   compromised device TO other internal devices:
   ```bash
   clickhouse-client --host <ch-host> --query \
     "SELECT dst_ip, dst_port, sum(bytes_out) AS total_bytes, count()
      FROM netsoldier.connections
      WHERE src_mac = '<device-mac>'
        AND dst_ip LIKE '192.168.%'
        AND dst_port NOT IN (53, 5353)
      GROUP BY dst_ip, dst_port
      ORDER BY total_bytes DESC
      FORMAT PrettyCompact"
   ```

5. **Remediate the device.** Factory reset or reimage the device. Change any
   passwords that were used on the device. If it is an IoT device with no user
   accounts, a firmware reset is sufficient.

6. **Unblock after remediation.** Revert the killswitch action via the web UI
   or API. The device will reappear in the device inventory once it reconnects.

7. **Post-incident.** Review the killswitch audit log. Add the C2 domain to
   the local threat list if it came from manual investigation rather than a
   feed. Consider updating allowlist and policy thresholds if the response was
   too slow or too aggressive.

---

## IR-3: False-positive storm

**Trigger:** A large number of alerts appear in a short time for benign
domains, or the killswitch has pending/active actions against legitimate
services.

**Steps:**

1. **Identify the bad IoC.** Filter alerts by source — a single feed update
   often causes false-positive storms. Note the matched IoC value.

2. **Reject all pending killswitch actions** related to the false positive:
   ```bash
   for id in $(curl -s http://killswitch-controller:8084/actions/pending | \
     jq -r '.[] | select(.blocked_domain == "<bad-domain>") | .id'); do
     curl -X POST "http://killswitch-controller:8084/actions/$id/reject" \
       -H 'Content-Type: application/json' \
       -d '{"reason": "false positive: feed error"}'
   done
   ```

3. **Revert any active blocks** caused by the false positive (same pattern
   with `/actions/active` and `/actions/$id/revert`).

4. **Remove the bad IoC.** If the IoC is in the local threat list
   (`domains.txt`), remove it and restart detection-engine. If it came from
   MISP or an external feed, disable or deprioritize that feed in
   threat-intel-sync configuration.

5. **Tune policy thresholds.** If auto-block triggered on a low-quality IoC,
   consider raising `POLICY_AUTO_CONFIDENCE` or changing
   `POLICY_AUTO_SEVERITY` to require `critical` severity.

6. **Add critical devices to the allowlist** if they are repeatedly targeted
   by false positives:
   ```bash
   # Update killswitch-controller env vars
   ALLOWLIST_MACS=<router-mac>,<nas-mac>
   ALLOWLIST_IPS=<router-ip>,<nas-ip>
   ```

---

## IR-4: Sensor blind — detection engine not polling

**Trigger:** `DetectionEnginePollErrors` Prometheus alert fires, or the Alerts
page shows no new entries despite active DNS traffic.

**Steps:**

1. **Check detection-engine health:**
   ```bash
   # Kubernetes
   kubectl logs -n netsoldier deploy/detection-engine --tail=50

   # Podman
   journalctl -u detection-engine --since "10 minutes ago"
   ```

2. **Check AdGuard connectivity.** The detection engine polls AdGuard's
   querylog API. Verify AdGuard is reachable:
   ```bash
   curl -sf -u admin:changeme http://adguard-web.dns.svc:3000/control/status
   ```

3. **If AdGuard is down**, DNS resolution still works (clients fall back to
   upstream) but threat detection is blind. Fix AdGuard first — see
   [Service Operations](service-operations.md).

4. **If AdGuard is up but polling fails**, check for authentication errors in
   detection-engine logs. Verify `ADGUARD_USER` and `ADGUARD_PASSWORD` env
   vars match the AdGuard configuration.

5. **Restart detection-engine** if the issue persists:
   ```bash
   kubectl rollout restart deploy/detection-engine -n netsoldier
   ```

6. **Verify recovery:** wait for the poll interval (30s default) and check
   that new entries appear on the Alerts page or in the detection-engine logs.

**Impact while blind:** DNS resolution continues normally. Devices are NOT
blocked and existing killswitch actions remain active. The system is fail-open
by design — a sensor failure never takes the network down.

---

## IR-5: Killswitch misfired — legitimate device blocked

**Trigger:** User reports connectivity loss for a specific device. The device
appears in the killswitch Active Blocks list.

**Steps:**

1. **Revert immediately.** In the web UI, click **Revert** on the active
   block. Enter a reason (e.g. "legitimate device, false positive").

2. **Verify connectivity is restored.** The device should regain DNS
   resolution within seconds (for DNS sinkhole) or network access within
   30 seconds (for ARP isolation).

3. **Add the device to the allowlist** to prevent recurrence:
   ```bash
   # Get current allowlist
   curl -s http://killswitch-controller:8084/allowlist

   # Add the device MAC/IP to ALLOWLIST_MACS or ALLOWLIST_IPS env vars
   ```

4. **Review the triggering alert.** Check whether the matched IoC is a false
   positive (see IR-3) or whether the device legitimately contacted a
   suspicious domain but should be allowed (e.g. a security tool checking
   against known-bad lists).

5. **Check the audit log** for the full action lifecycle:
   ```bash
   clickhouse-client --host <ch-host> --query \
     "SELECT timestamp, from_state, to_state, actor, reason
      FROM netsoldier.audit_log
      WHERE action_id = '<action-id>'
      ORDER BY timestamp
      FORMAT PrettyCompact"
   ```
