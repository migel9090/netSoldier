-- Zeek Intel framework hits (step 107): IoC observations on live
-- traffic (DOMAIN via SNI/DNS/cert, ADDR, JA3, first-party JA4, ...).
CREATE TABLE IF NOT EXISTS netsoldier.zeek_intel (
    timestamp      DateTime,
    uid            String,
    src_ip         String,
    src_port       UInt16,
    dst_ip         String,
    dst_port       UInt16,
    indicator      String,
    indicator_type LowCardinality(String),
    seen_where     LowCardinality(String),
    matched        Array(String),
    sources        Array(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, indicator)
TTL timestamp + INTERVAL 30 DAY;
