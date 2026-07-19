-- ml-anomaly beacon detections derived from RITA threat_mixtape
-- (step 112). detection-engine's unified ingest tails this table.
CREATE TABLE IF NOT EXISTS netsoldier.ml_beacons (
    timestamp        DateTime DEFAULT now(),
    src_ip           String,
    dst_ip           String,
    dst_domain       String DEFAULT '',
    beacon_score     Float64,
    connection_count UInt32,
    confidence       UInt8,
    severity         LowCardinality(String),
    beacon_type      LowCardinality(String) DEFAULT '',
    tags             Array(String)
) ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;
