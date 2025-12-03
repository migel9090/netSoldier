# Threat model — STRIDE analysis for netSoldier

- **Date:** 2026-06-03
- **Status:** Living document (update with each phase)
- **Scope:** full netSoldier system — monitoring, detection, killswitch, DevSecOps pipeline
- **Method:** STRIDE per component/data-flow, with risk ratings and planned mitigations
- **Reference:** [ADR-0001](adr/0001-architektura.md), [`context/03-architecture.md`](../context/03-architecture.md)

## 1. System description

netSoldier is a passive home-network IDS with an out-of-band killswitch. It is
**never inline** — a sensor failure cannot take the network down (fail-open by
design). The system runs on two profiles: a full `proxmox-soc` stack (~8 GB
server) and a minimal `pi-edge` profile (Pi 3B+, 1 GB).

Key architectural invariant: **the sensor observes; it does not route**. All
enforcement actions (DNS sinkhole, ARP isolation, switch ACL) are out-of-band
and reversible (TTL auto-revert).

## 2. Trust boundaries

```
  TB-1                       TB-2                         TB-3
Internet ──── ISP Router ──── Managed Switch ──── SPAN (one-way) ──── netSoldier sensor
                │                   │                                      │
                │ WiFi clients      │ Wired devices              TB-4     │
                │                   │                  ┌──────────────────┤
                │                   │                  │ k8s / Podman     │
                │                   │                  │  ┌───────────────┤
                │                   │                  │  │ internal svcs │
                │                   │                  │  └───────────────┘
                │                   │                  └──────────────────┘
                │                   │                          │
                │                   │ TB-5 (enforcement)       │ TB-6
                │                   │◄─────────────────────────│ (external feeds)
                │                   │ switch ACL/VLAN          │ abuse.ch, GreyNoise,
                │                   │ ARP injection            │ Spamhaus, MISP
                │                   │ AdGuard sinkhole         │
                │                                              │ TB-7
                │                                              │ (admin)
                │                                     Web UI / Grafana ◄── operator
                │
                │ TB-8 (CI/CD supply chain)
                └── GitHub → Actions → GHCR → ArgoCD → cluster
```

| Boundary | Between | Trust level |
|---|---|---|
| TB-1 | Internet ↔ ISP router | Untrusted ↔ boundary device (uncontrolled) |
| TB-2 | ISP router ↔ home LAN | Boundary ↔ semi-trusted LAN |
| TB-3 | LAN (SPAN mirror) → netSoldier sensor | Semi-trusted → trusted (one-way, passive) |
| TB-4 | netSoldier host ↔ containerized services | Trusted host ↔ least-privilege containers |
| TB-5 | netSoldier → network enforcement points | Trusted → semi-trusted (switch, ARP, AdGuard) |
| TB-6 | External feeds → netSoldier | Untrusted → trusted (ingest with validation) |
| TB-7 | Admin/operator → Web UI / Grafana | Trusted (authenticated) → trusted |
| TB-8 | Developer → CI/CD → deployment | Trusted dev → pipeline with gates → cluster |

## 3. Data flows

| ID | From → To | Data | Channel |
|---|---|---|---|
| DF-01 | All devices → AdGuard Home | DNS queries | UDP/TCP 53, DoH/DoT |
| DF-02 | Switch SPAN → sensor NIC | Mirrored packets | Passive Ethernet (one-way) |
| DF-03 | Sensor → Suricata/Zeek/ntopng | Raw packets | AF_PACKET fanout |
| DF-04 | Suricata/Zeek → detection-engine | EVE JSON, conn/dns logs | File/socket/API |
| DF-05 | detection-engine → ClickHouse | Correlated events, flows | TCP (ClickHouse native) |
| DF-06 | External feeds → threat-intel-sync | IoC lists (domains/IPs/hashes) | HTTPS |
| DF-07 | threat-intel-sync → AdGuard/Suricata/Zeek | Rules, blocklists, Intel data | API/file |
| DF-08 | detection-engine → killswitch-controller | Detection events + confidence | Internal API |
| DF-09 | killswitch-controller → enforcement | Sinkhole / ARP / switch commands | AdGuard API, raw socket, SNMP/SSH |
| DF-10 | killswitch-controller → ClickHouse | Audit log (append-only) | TCP |
| DF-11 | Admin → Web UI | Approve/reject/revert killswitch | HTTPS |
| DF-12 | Services → Prometheus/Loki/OTel | Metrics, logs, traces | HTTP/gRPC |
| DF-13 | Fluent Bit (edge) → Vector (server) | Forwarded logs | TCP/TLS |
| DF-14 | Developer → GitHub → CI → GHCR → ArgoCD | Code, images, manifests | HTTPS + SSH |
| DF-15 | MISP → threat-intel-sync | Aggregated threat intel | REST API |
| DF-16 | ml-anomaly → detection-engine | Anomaly scores (beaconing, volumetric) | Internal API |

## 4. STRIDE analysis

Risk rating: **Impact** (Critical / High / Medium / Low) x **Likelihood** (High / Medium / Low / Very Low).

### Spoofing

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| S-01 | Device configures static DNS, bypassing AdGuard | DF-01, AdGuard | High — complete evasion of DNS visibility for that device | Medium — malware or savvy user can do this | **High** | Monitor for DNS traffic to non-AdGuard resolvers via SPAN (Suricata/Zeek rule on port 53/443 to unknown DNS). Alert on bypass. Cannot fully prevent without inline firewall (out of scope — ISP router is uncontrolled). |
| S-02 | MAC address spoofing / randomization to evade device inventory or allowlist | device-inventory, killswitch | Medium — evade per-device tracking; could impersonate an allowlisted device | Medium — MAC randomization is default on modern clients; targeted spoofing requires LAN access | **Medium** | Correlate MAC with DHCP option 55/60 fingerprint, hostname, and OUI. Use stable composite device ID (step 59–60). Alert on MAC-to-fingerprint mismatch. Allowlist should include fingerprint, not MAC alone. |
| S-03 | Compromised or rogue threat-intel feed injects false IoCs | DF-06, threat-intel-sync | High — false IoCs trigger false detections → unwarranted blocking of legitimate traffic | Low — abuse.ch/GreyNoise/Spamhaus are reputable; requires compromise of upstream provider | **Medium** | Validate feed TLS certificates. Pin feed URLs. Track IoC source in detections. Composite confidence scoring (step 116) — a single-source IoC match alone does not trigger auto-block. Monitor feed freshness and anomalous volume spikes (step 134). |
| S-04 | ARP spoofing by compromised LAN device to poison sensor's device inventory | device-inventory, DF-02 | Medium — polluted IP-MAC mapping; could mask real device identity | Low — requires compromised device on LAN | **Low** | Passive ARP observation from SPAN (sensor does not trust ARP replies directed at it). Cross-reference with DHCP leases. Detect ARP storms/conflicts as a detection rule. |
| S-05 | Spoofed or compromised container image deployed to cluster | DF-14, ArgoCD | Critical — arbitrary code execution in production | Very Low — mitigated by cosign + SLSA + Kyverno verifyImages + SHA-pinned actions | **Medium** | Cosign keyless signing (step 20), SLSA L2 provenance (step 21), Kyverno verifyImages admission policy (step 35), all CI actions pinned to SHAs (step 14), Harden-Runner egress monitoring. Renovate automerge OFF (step 23). |

### Tampering

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| T-01 | Attacker modifies SPAN-mirrored traffic | DF-02 | High — blind the sensor or inject false alerts | Very Low — SPAN is a physical one-way mirror; would require physical access to the switch | **Low** | Physical security of the switch. SPAN port configured as destination-only (no TX). Detect if SPAN feed drops to zero (monitoring alert). |
| T-02 | Tampering with ClickHouse data (alter/delete events or audit log) | DF-05, DF-10 | Critical — destroy forensic evidence or hide attacker activity | Low — requires access to ClickHouse (no public exposure, k8s NetworkPolicy) | **Medium** | ClickHouse not exposed outside cluster (NetworkPolicy, step 92). Killswitch audit log is append-only by design (step 69). Least-privilege service accounts (step 92). Backup and integrity checks (step 95). |
| T-03 | Tampering with killswitch allowlist to add attacker's device | killswitch-controller | Critical — attacker's device becomes unblockable | Low — requires API access or GitOps manifest modification | **Medium** | Allowlist stored in version-controlled config (Git). Changes require PR review (branch protection, step 12). API authentication required (step 73). Audit log records allowlist changes. |
| T-04 | Tampering with detection rules (Suricata/Zeek) to create blind spots | DF-07, detections/ | High — targeted evasion of specific detections | Low — rules in Git, changes require PR + CI (PCAP replay regression test, step 89/124) | **Low** | Detection-as-code: rules versioned in Git. PCAP corpus replay in CI catches regressions (step 89). PR review required. Rule update automation includes regression test (step 161). |
| T-05 | Tampering with ArgoCD manifests or Helm values | DF-14, deploy/ | Critical — deploy modified workloads, disable security controls | Very Low — branch protection + PR review + cosign verification | **Low** | Git branch protection (step 12). Kyverno admission policies (step 35). ArgoCD sync from Git only. SOPS for secrets (step 34). |

### Repudiation

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| R-01 | Killswitch action performed without traceable audit trail | killswitch-controller | High — cannot reconstruct who approved what, when | Low — audit log is a core design requirement | **Low** | Append-only audit log to ClickHouse with immutable timestamps (step 69). Every state transition (pending/approved/active/reverted) recorded with actor identity, reason, and affected device. |
| R-02 | Admin denies approving a killswitch action | DF-11, Web UI | Medium — accountability gap | Low — admin authentication is planned | **Low** | Authenticated sessions for Web UI (OIDC planned, step 159). Audit log ties approval to authenticated identity. |
| R-03 | Configuration change (allowlist, thresholds, rules) without audit trail | All config surfaces | Medium — cannot attribute misconfigurations | Medium — early phases may lack comprehensive change logging | **Medium** | Git is the source of truth for all config (GitOps). Git history provides full attribution. Add application-level config-change events to ClickHouse audit (step 160). |

### Information disclosure

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| I-01 | DNS query logs expose browsing history of household members | ClickHouse, AdGuard, Loki | High — privacy violation even with consent; data breach if exfiltrated | Medium — data exists by design; risk is unauthorized access | **High** | Household consent documented (ethics section). Access restricted to authenticated admin only. ClickHouse + Grafana behind authentication (step 159). 30-day default retention with configurable TTL (step 83). Data classified as sensitive in privacy review (step 142). No payload inspection — metadata only. |
| I-02 | Network topology and device inventory leaked | device-inventory, Web UI | Medium — attacker learns network layout for targeted attacks | Low — services not exposed to internet; LAN-only | **Low** | Services bound to cluster-internal IPs (NetworkPolicy, step 92). Web UI requires authentication. No internet-facing exposure. |
| I-03 | ClickHouse/Grafana/Web UI accessible without authentication (early phases) | DF-05, DF-12 | High — full access to all collected network data | Medium — early development may skip auth; LAN devices can reach services | **High** | Prioritize basic auth even in Phase 0 (port-forward only for dev). Full OIDC/SSO in step 159. NetworkPolicies restrict access paths (step 92). |
| I-04 | SOPS age private key compromised | security/, SOPS | Critical — all encrypted secrets decryptable (DB passwords, API keys, switch credentials) | Low — key stored locally, not in repo | **Medium** | Age key never committed to Git (.gitignore). Key rotation procedure (step 167). Limit key distribution. Backup key encrypted separately. |
| I-05 | Observability data (traces, metrics) leaks service internals | DF-12, Prometheus/Loki | Low — operational data, not user-facing | Low — internal services only | **Very Low** | Cluster-internal exposure only. No PII in metric labels. |

### Denial of service

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| D-01 | DNS query flood against AdGuard Home | DF-01, AdGuard | Critical — all household devices lose DNS resolution (effectively offline) | Low — requires compromised LAN device generating sustained flood | **Medium** | AdGuard rate-limiting per client. Monitor AdGuard resource usage (Prometheus). If AdGuard is down, devices fall back to ISP router DNS (fail-open). Resource limits in container orchestration. Detect anomalous query volume as a detection rule. |
| D-02 | ClickHouse storage exhaustion halts detection pipeline | DF-05, ClickHouse | High — new events dropped; detection goes blind | Medium — high-traffic bursts or misconfigured retention | **High** | TTL-based retention (30 days hot, step 83). Disk usage alerts in Prometheus. Cold tier to MinIO/S3 (step 119). Resource limits and PersistentVolume size monitoring. Backpressure in pipeline (step 133). |
| D-03 | Crafted traffic overwhelms sensor CPU (Suricata/Zeek) | DF-02, DF-03 | High — detection blind spot during attack | Low — requires high-bandwidth attack on LAN; Pi profile already has limited ruleset | **Medium** | Tuned AF_PACKET ring sizes and thread pinning (step 104). Reduced Suricata ruleset on Pi. Drop-rate monitoring with alerts (step 99). eBPF/XDP pre-filtering in Phase 3 (step 151). Sensor saturation does not affect network (fail-open). |
| D-04 | False-positive storm triggers mass killswitch blocking | killswitch-controller | Critical — legitimate devices quarantined; household loses connectivity | Low — composite confidence and human-in-the-loop designed to prevent this | **Medium** | Composite confidence scoring — weak signals alone never trigger auto-block (step 116). Only high-confidence IoC/signature matches auto-block, and only via DNS sinkhole (least disruptive). Everything else queues for human approval (step 12 in ADR). Allowlist protects critical devices. TTL auto-revert limits blast radius (step 68). Rate-limit concurrent enforcement actions. FP feedback loop (step 118). |
| D-05 | Pi 3B+ resource exhaustion (1 GB RAM, USB2 NIC) | pi-edge profile | Medium — edge monitoring degrades or crashes | High — the Pi is inherently resource-constrained | **High** | Minimal `pi-edge` profile: AdGuard + device-inventory + Fluent Bit only. Feature flags disable heavy components (Suricata limited ruleset or OFF, Zeek OFF, step 84). Resource limits per container. Performance baseline documents actual limits (step 99). Degradation does not affect network (fail-open). |

### Elevation of privilege

| ID | Threat | Target | Impact | Likelihood | Risk | Mitigation |
|---|---|---|---|---|---|---|
| E-01 | Container escape to host | TB-4, any container | Critical — full host access; pivot to all services and enforcement | Very Low — distroless images, non-root, read-only rootfs, seccomp/AppArmor, dropped capabilities | **Low** | Non-root containers (step 91). Read-only root filesystem. Seccomp and AppArmor profiles (step 91). Drop all capabilities except required. Kyverno enforces these at admission (step 35). Minimal distroless base images (step 10). |
| E-02 | Web UI or API vulnerability → unauthorized killswitch control | DF-11, Web UI, killswitch API | Critical — attacker can block or unblock arbitrary devices | Low — authenticated API; standard web security practices | **Medium** | API authentication and authorization (step 73). Input validation. CSRF/XSS protections in SvelteKit. Rate limiting. Security review and pen-test (step 141). |
| E-03 | ArgoCD compromise → deploy arbitrary workloads | DF-14, ArgoCD | Critical — full cluster takeover | Very Low — ArgoCD password changed from default (step 33); SOPS secrets; Kyverno verifyImages blocks unsigned images | **Low** | ArgoCD credentials via SOPS (step 33). Kyverno blocks unsigned images (step 35). RBAC for ArgoCD (least privilege). Git branch protection. |
| E-04 | Compromised MISP instance → inject false threat intel → automated false blocking | DF-15, MISP, killswitch | High — attacker controls what gets blocked via poisoned intel | Low — MISP is internal, not internet-facing; feeds are from reputable sources | **Medium** | MISP not exposed externally. Feed sources validated (TLS, known endpoints). Composite confidence — single-source IoC alone triggers approval queue, not auto-block. Monitor IoC freshness and volume anomalies (step 134). MISP hardening and key rotation (step 134). |
| E-05 | Compromised LAN device pivots to netSoldier services | TB-3 → TB-4 | High — access to detection and enforcement APIs from inside the network | Medium — IoT devices on home LANs are frequently compromised | **High** | NetworkPolicies restrict service-to-service communication (step 92). Services not exposed on LAN (ClusterIP only; admin access via port-forward or ingress with auth). VLAN segmentation between netSoldier host and general LAN (if switch supports). Host firewall (nftables, step 30). Service authentication for all APIs. |

## 5. Critical threat summary (sorted by risk)

| Risk | IDs | Theme |
|---|---|---|
| **High** | I-01, I-03, D-02, D-05, E-05 | Data privacy, storage exhaustion, resource limits, LAN pivot |
| **Medium** | S-02, S-03, S-05, T-02, T-03, R-03, I-04, D-01, D-03, D-04, E-02, E-04 | Feed integrity, audit gaps, killswitch abuse, sensor saturation |
| **Low** | S-04, T-01, T-04, T-05, R-01, R-02, I-02, I-05, E-01, E-03 | Physical, supply chain (mitigated), internal-only exposure |

## 6. Mitigations mapped to roadmap steps

| Mitigation | Addresses | Roadmap step(s) |
|---|---|---|
| Composite confidence scoring (no single-signal auto-block) | S-03, D-04, E-04 | 116–117 |
| Killswitch allowlist + TTL auto-revert + append-only audit | T-03, D-04, R-01 | 68–69 |
| Human-in-the-loop approval for non-high-confidence | D-04, E-04 | 68, 73–74 |
| NetworkPolicies + RBAC | T-02, I-02, I-03, E-05 | 92 |
| Authentication for Web UI and APIs | I-01, I-03, E-02, R-02 | 73, 159–160 |
| Container hardening (non-root, RO-FS, seccomp, distroless) | E-01 | 10, 35, 91 |
| Cosign + SLSA + Kyverno verifyImages | S-05, T-05 | 20–21, 35 |
| ClickHouse retention TTL + cold tier + disk alerts | D-02 | 83, 119 |
| Pi-edge minimal profile + feature flags | D-05 | 84, 99 |
| Detection-as-code (PCAP replay regression) | T-04 | 89, 124 |
| SOPS + age key management | I-04 | 34, 167 |
| Feed validation + freshness monitoring | S-03, E-04 | 134 |
| DNS bypass detection (non-AdGuard resolver traffic) | S-01 | 43 (extend with SPAN rule) |
| Composite device ID (beyond MAC alone) | S-02 | 59–60 |
| Pen-test + security review | E-02, E-05, T-03 | 141, 169 |
| Privacy review + data retention policies | I-01 | 142, 164 |
| Host hardening (nftables, fail2ban, SSH) | E-05 | 30 |

## 7. Accepted risks and residual exposure

| Risk | Acceptance rationale |
|---|---|
| **ISP router is uncontrolled** — cannot enforce DNS at the firewall level, cannot prevent static DNS bypass entirely | Closed device; DNS bypass is *detected* via SPAN even if not prevented. Full mitigation requires replacing the router (out of scope). |
| **WiFi DPI blind spot until Phase 3** — WiFi traffic between clients and internet stays inside the ISP router and is invisible at the packet level | Mitigated by DNS visibility (all WiFi queries go through AdGuard) and metadata. Full DPI deferred to Phase 3 (dedicated AP behind switch, step 152–153). |
| **Out-of-band enforcement latency (seconds, not microseconds)** — the killswitch reacts in seconds, not real-time inline | Acceptable for a home network. Inline IPS was explicitly rejected (fail-open safety requirement, ADR-0001). |
| **ECH erosion of SNI visibility (~50% of clients by ~2026)** — Encrypted Client Hello hides SNI from passive observation | Mitigated by DNS-first design: AdGuard sees the query before ECH hides the SNI. JA4 fingerprinting still works. Residual: if a device uses DoH to a non-AdGuard resolver AND ECH, visibility is limited to IP/flow metadata. |
| **8 GB server budget is tight** — may require disabling Zeek or Arkime under memory pressure | Feature flags in Helm values control which components are active. Performance baseline (step 99) documents actual limits. |
| **Single operator** — no segregation of duties; the admin is the developer is the reviewer | Acceptable for a personal/educational project. Git history and audit logs provide accountability. |

## 8. Assumptions

1. The home network is **not the target** — threats are compromised IoT devices, malware on endpoints, or network-borne attacks traversing the LAN. netSoldier defends; it does not attack.
2. **Household consent** is in place for all monitoring.
3. The **ISP router cannot be replaced or configured** beyond DHCP settings.
4. **Physical security** of the switch, Pi, and server is adequate (indoor, private residence).
5. **External threat intel feeds** (abuse.ch, GreyNoise, Spamhaus) are operated in good faith; compromise of a major feed provider is a low-probability event.
6. The **developer/operator is trusted** — insider threat is out of scope for a single-person project.

## 9. Review schedule

This threat model is a living document. Update at:
- Each roadmap audit gate (steps 25, 50, 75, 100, 125, 150, 172)
- When new components are added (Suricata/Zeek in Phase 2, eBPF in Phase 3)
- When the network topology changes (managed switch purchase, dedicated AP)
- After any security incident or pen-test finding (step 141)
