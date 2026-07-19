-- ml-anomaly Isolation Forest flow anomalies (step 113): per-source
-- window aggregates that deviate from the household baseline. Feature
-- snapshot is stored alongside the score so an analyst can see *why*
-- a window was flagged. detection-engine's unified ingest tails this
-- table as the volumetric signal for composite-confidence (step 116).
CREATE TABLE IF NOT EXISTS netsoldier.ml_anomalies (
    timestamp       DateTime DEFAULT now(),
    window_start    DateTime,
    src_ip          String,
    anomaly_score   Float64,
    confidence      UInt8,
    severity        LowCardinality(String),
    conn_count      UInt32,
    bytes_out       UInt64,
    bytes_in        UInt64,
    dst_fanout      UInt32,
    port_fanout     UInt32,
    avg_duration_ms Float64,
    model_version   LowCardinality(String),
    tags            Array(String)
) ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (src_ip, window_start)
TTL timestamp + INTERVAL 30 DAY;
