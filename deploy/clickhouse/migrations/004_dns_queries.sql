CREATE TABLE IF NOT EXISTS netsoldier.dns_queries (
    timestamp    DateTime,
    client_ip    String,
    domain       String,
    query_type   LowCardinality(String),
    answer       String,
    status       LowCardinality(String),
    response_ms  UInt16,
    blocked      UInt8
) ENGINE = MergeTree()
ORDER BY (timestamp, client_ip, domain)
TTL timestamp + INTERVAL 30 DAY;
