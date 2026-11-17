-- ml_beacons keeps every destination name (step 125.23 follow-up).
--
-- 021 keyed the table on (timestamp, src_ip, dst_ip). A beacon found on TLS
-- server names has no destination address - ml-anomaly writes dst_ip '' and
-- the name in dst_domain - so two SNI beacons of one device stamped with the
-- same second shared a key, and the ReplacingMergeTree kept only one of them
-- when it merged. The destination name joins the key.
--
-- A sorting key can only be extended with a column added in the same ALTER,
-- and dst_domain exists, so the table is rebuilt: copy into a staging table
-- with the new key, swap the two with EXCHANGE TABLES (atomic), copy the rows
-- that arrived during the copy, drop the old table. ingested_at is copied as
-- it is: detection-engine's cursor runs on it, and a reset value would make
-- the whole history look new. Partition, TTL and the ingested_at index are
-- those of 021 and 026.
--
-- Rows written while this runs. The copy reads the parts that exist when it
-- starts; a row ml-anomaly inserts after that lands in the old table. Before
-- the swap the newest ingested_at in the copy is noted, and after it every
-- row of the old table that arrived later is copied across, so nothing the
-- beacon worker writes during the rebuild is lost.
--
-- Safe to re-run from the top after failing part-way: the staging tables of
-- an earlier attempt are dropped first. Before the swap they hold a partial
-- copy; after it the live table already holds what the copy did. Only a
-- failure between the swap and the catch-up insert, with the worker writing
-- in those seconds, can lose the rows it wrote then.

DROP TABLE IF EXISTS netsoldier.ml_beacons_032;
DROP TABLE IF EXISTS netsoldier.ml_beacons_032_mark;

CREATE TABLE netsoldier.ml_beacons_032
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
    tags             Array(String),
    ingested_at      DateTime64(3) DEFAULT now64(3),
    INDEX ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1
)
ENGINE = ReplacingMergeTree(timestamp)
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip, dst_domain)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.ml_beacons_032
    (timestamp, src_ip, dst_ip, dst_domain, beacon_score, connection_count,
     confidence, severity, beacon_type, tags, ingested_at)
SELECT timestamp, src_ip, dst_ip, dst_domain, beacon_score, connection_count,
       confidence, severity, beacon_type, tags, ingested_at
FROM netsoldier.ml_beacons;

CREATE TABLE netsoldier.ml_beacons_032_mark
ENGINE = Memory
AS SELECT max(ingested_at) AS mark FROM netsoldier.ml_beacons_032;

EXCHANGE TABLES netsoldier.ml_beacons AND netsoldier.ml_beacons_032;

INSERT INTO netsoldier.ml_beacons
    (timestamp, src_ip, dst_ip, dst_domain, beacon_score, connection_count,
     confidence, severity, beacon_type, tags, ingested_at)
SELECT timestamp, src_ip, dst_ip, dst_domain, beacon_score, connection_count,
       confidence, severity, beacon_type, tags, ingested_at
FROM netsoldier.ml_beacons_032
WHERE ingested_at > (SELECT mark FROM netsoldier.ml_beacons_032_mark);

DROP TABLE netsoldier.ml_beacons_032;
DROP TABLE netsoldier.ml_beacons_032_mark;
