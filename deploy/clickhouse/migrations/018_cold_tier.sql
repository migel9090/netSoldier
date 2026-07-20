-- Cold tier (step 119). storage.xml defines the `tiered` policy: volume
-- `default` = local hot disk, volume `cold` = S3 disk backed by in-cluster
-- MinIO (bucket netsoldier-cold, prefix native/). Aged parts move to the
-- cold volume at each table's previous delete horizon, and total retention
-- is extended now that history no longer competes for the 20Gi hot PVC.
-- Historical queries stay transparent: the table reads both volumes.
--
-- Scope: append-only MergeTree time-series tables only. The
-- ReplacingMergeTree state tables (ml_beacons, ml_anomalies,
-- detection_feedback) keep their delete-only TTLs — they hold current
-- state, merges rewrite them continuously (bad fit for S3 parts), and the
-- daily Parquet cold-export already archives them. `devices` is a
-- reference table with no TTL.
--
-- Cold copies are deleted after 365 days, except audit_log (2 years:
-- killswitch/approval audit trail).

ALTER TABLE netsoldier.network_flows MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.network_flows MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.dns_queries MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.dns_queries MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.connections MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.connections MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.device_events MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.device_events MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.alerts MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.alerts MODIFY TTL timestamp + INTERVAL 90 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.events MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.events MODIFY TTL timestamp + INTERVAL 90 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.suricata_alerts MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.suricata_alerts MODIFY TTL timestamp + INTERVAL 90 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.suricata_dns MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.suricata_dns MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.suricata_tls MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.suricata_tls MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_conn MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_conn MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_dns MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_dns MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_ssl MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_ssl MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_x509 MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_x509 MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_http MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_http MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.zeek_intel MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.zeek_intel MODIFY TTL timestamp + INTERVAL 30 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE;

ALTER TABLE netsoldier.audit_log MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE netsoldier.audit_log MODIFY TTL timestamp + INTERVAL 180 DAY TO VOLUME 'cold', timestamp + INTERVAL 730 DAY DELETE;
