CREATE TABLE IF NOT EXISTS netsoldier.alerts (
    timestamp    DateTime,
    id           String,
    domain       String,
    client_ip    String,
    query_type   LowCardinality(String),
    matched_ioc  String,
    severity     LowCardinality(String),
    source       LowCardinality(String),
    acknowledged UInt8 DEFAULT 0
) ENGINE = ReplacingMergeTree()
ORDER BY (timestamp, id);
