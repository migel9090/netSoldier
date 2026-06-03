# observability/ — dashboards, rules and telemetry config as code

| Content | Purpose | Lands at |
|---|---|---|
| Grafana dashboards (JSON) | System Health, Network Overview, DNS & Threat-Intel, Killswitch & Audit, DPI & Protocols, Beaconing & Anomalies | steps 48, 79–81, 121–122 |
| Prometheus / Loki rules | alert rules (critical IoC, device offline, approval queue, SLO breaches) | steps 48, 82, 137 |
| Grafana Alloy config | logs/metrics collection (Alloy replaces Promtail — EOL 2026) | step 39 |
| OTel Collector config | traces from Go/Python services → Collector/Tempo | step 40 |

Everything here deploys via GitOps (ArgoCD) — no click-ops dashboards; the UI is
read-only evidence of what Git says.
