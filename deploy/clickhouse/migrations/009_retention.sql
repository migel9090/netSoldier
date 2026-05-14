ALTER TABLE netsoldier.alerts MODIFY TTL timestamp + INTERVAL 90 DAY;
ALTER TABLE netsoldier.audit_log MODIFY TTL timestamp + INTERVAL 180 DAY;
