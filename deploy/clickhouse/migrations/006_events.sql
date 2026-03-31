CREATE TABLE IF NOT EXISTS netsoldier.events (
    timestamp    DateTime,
    source       LowCardinality(String),
    level        LowCardinality(String),
    message      String,
    metadata     String
) ENGINE = MergeTree()
ORDER BY (timestamp, source)
TTL timestamp + INTERVAL 90 DAY;
