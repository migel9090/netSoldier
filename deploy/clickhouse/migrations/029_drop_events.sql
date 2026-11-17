-- Drop the generic events table (step 125.10, audit DP-11).
--
-- events held the Suricata EVE records the Vector aggregator did not route
-- elsewhere (stats, netflow, ...), forwarded by Fluent Bit from a host log
-- file that no profile mounts. Nothing ever wrote it and nothing reads it:
-- no service, dashboard or job. The Suricata sidecar writes the EVE records
-- netSoldier uses into suricata_alerts, suricata_dns and suricata_tls.
DROP TABLE IF EXISTS netsoldier.events;
