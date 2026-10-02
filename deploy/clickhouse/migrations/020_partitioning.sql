-- Partition the high-volume tables by month (step 124).
--
-- No table had a PARTITION BY at all, so every TTL expiry (30/90/180/365
-- days) had to rewrite data parts instead of dropping a whole partition.
-- That is the expensive path, and it lands squarely on the documented
-- bottleneck: the Pi profile's µSD card does ~5 MB/s random write
-- (docs/performance-baseline.md). The S3 cold-tier move added in step 119
-- also works per-part, so date partitions make both retention and tiering
-- cheap instead of continuous.
--
-- ClickHouse cannot add a partition key to an existing MergeTree table, so
-- this migration creates partitioned replacements and swaps them in. Run it
-- during a maintenance window; see docs/runbooks/data-maintenance.md (DM-9).
--
-- Tables are handled newest-data-first so the most valuable history is
-- migrated even if the window runs out.

-- ── dns_queries (highest volume) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS netsoldier.dns_queries_partitioned
(
    timestamp   DateTime,
    client_ip   String,
    client_mac  String DEFAULT '',
    domain      String,
    query_type  LowCardinality(String),
    answer      String DEFAULT '',
    status      LowCardinality(String) DEFAULT '',
    response_ms UInt16 DEFAULT 0,
    blocked     UInt8 DEFAULT 0
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, client_ip, domain)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.dns_queries_partitioned SELECT * FROM netsoldier.dns_queries;
EXCHANGE TABLES netsoldier.dns_queries AND netsoldier.dns_queries_partitioned;
DROP TABLE IF EXISTS netsoldier.dns_queries_partitioned;

-- ── connections ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS netsoldier.connections_partitioned AS netsoldier.connections
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_mac, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.connections_partitioned SELECT * FROM netsoldier.connections;
EXCHANGE TABLES netsoldier.connections AND netsoldier.connections_partitioned;
DROP TABLE IF EXISTS netsoldier.connections_partitioned;

-- ── network_flows ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS netsoldier.network_flows_partitioned AS netsoldier.network_flows
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;

INSERT INTO netsoldier.network_flows_partitioned SELECT * FROM netsoldier.network_flows;
EXCHANGE TABLES netsoldier.network_flows AND netsoldier.network_flows_partitioned;
DROP TABLE IF EXISTS netsoldier.network_flows_partitioned;

-- ── alerts (90 day TTL) ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS netsoldier.alerts_partitioned AS netsoldier.alerts
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, id)
TTL timestamp + INTERVAL 90 DAY;

INSERT INTO netsoldier.alerts_partitioned SELECT * FROM netsoldier.alerts;
EXCHANGE TABLES netsoldier.alerts AND netsoldier.alerts_partitioned;
DROP TABLE IF EXISTS netsoldier.alerts_partitioned;

-- ── audit_log (180 day TTL; partition by year, it is low volume) ──────────
CREATE TABLE IF NOT EXISTS netsoldier.audit_log_partitioned AS netsoldier.audit_log
ENGINE = MergeTree()
PARTITION BY toYYYY(timestamp)
ORDER BY (timestamp, action_id)
TTL timestamp + INTERVAL 180 DAY;

INSERT INTO netsoldier.audit_log_partitioned SELECT * FROM netsoldier.audit_log;
EXCHANGE TABLES netsoldier.audit_log AND netsoldier.audit_log_partitioned;
DROP TABLE IF EXISTS netsoldier.audit_log_partitioned;
