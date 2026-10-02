-- Stop collapsing beacon history (step 124).
--
-- ml_beacons was ReplacingMergeTree(timestamp) ORDER BY (src_ip, dst_ip), so
-- after a merge only the NEWEST beacon per source→destination pair survived.
-- Two things broke as a result: an analyst lost the history that makes a
-- beacon credible, and detection-engine's poller — which tails this table on
-- a timestamp cursor — could have rows vanish from under it between polls,
-- dropping the "beacon" signal that composite-confidence depends on.
--
-- Including timestamp in the sort key keeps each observation, and the
-- partition key makes the 30-day TTL a partition drop.
CREATE TABLE IF NOT EXISTS netsoldier.ml_beacons_v2
(
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
)
ENGINE = ReplacingMergeTree(timestamp)
PARTITION BY toYYYYMM(timestamp)
-- timestamp first: each observation is its own row, deduplicated only on an
-- exact (time, src, dst) repeat rather than collapsed per pair.
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.ml_beacons_v2 SELECT * FROM netsoldier.ml_beacons;
EXCHANGE TABLES netsoldier.ml_beacons AND netsoldier.ml_beacons_v2;
DROP TABLE IF EXISTS netsoldier.ml_beacons_v2;

-- ml_anomalies keeps its (src_ip, window_start) key: one verdict per flow
-- window is the correct semantic there, and window_start already spreads
-- rows over time. It only needs the partition key.
CREATE TABLE IF NOT EXISTS netsoldier.ml_anomalies_v2 AS netsoldier.ml_anomalies
ENGINE = ReplacingMergeTree(timestamp)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (src_ip, window_start)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.ml_anomalies_v2 SELECT * FROM netsoldier.ml_anomalies;
EXCHANGE TABLES netsoldier.ml_anomalies AND netsoldier.ml_anomalies_v2;
DROP TABLE IF EXISTS netsoldier.ml_anomalies_v2;
