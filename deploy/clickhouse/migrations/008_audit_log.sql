CREATE TABLE IF NOT EXISTS netsoldier.audit_log (
    timestamp    DateTime,
    action_id    String,
    from_state   LowCardinality(String),
    to_state     LowCardinality(String),
    actor        String,
    reason       String,
    detection_id String,
    target_mac   String,
    target_ip    String,
    action_type  LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, action_id);
