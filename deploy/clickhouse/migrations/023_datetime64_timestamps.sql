-- Millisecond timestamps for the enforcement audit log and device sightings
-- (step 125.8, contract v2 section 6).
--
-- killswitch-controller and device-inventory send '2006-01-02 15:04:05.000'
-- (UTC). A DateTime column rejects the fractional part, so every one of those
-- inserts failed and audit_log stayed empty. DateTime64(3) accepts it, and
-- keeps two transitions of one action within the same second in order.
--
-- `timestamp` is in both tables' sorting key (and in audit_log's partition
-- key), and ClickHouse refuses to retype a key column in place ("ALTER of key
-- column timestamp is forbidden"), so each table is rebuilt: copy into a
-- staging table with the new type, swap the two with EXCHANGE TABLES (atomic),
-- drop the old one. Existing rows keep their whole-second values (.000).
--
-- Carried over from 018 and 020: storage policy `tiered`, the move to the cold
-- volume and the delete horizon of each table, and audit_log's yearly
-- partition. device_events also gets the monthly partition 020 gave the other
-- high-volume tables, so its TTL drops whole partitions instead of rewriting
-- parts. ClickHouse 24.3 does not accept a DateTime64 TTL expression ("TTL
-- expression result column should have DateTime or Date type"), hence
-- toDateTime(timestamp) in the TTL clauses; it only drops the milliseconds,
-- which does not matter at day granularity.
--
-- Safe to re-run from the top after failing part-way, which is what the
-- runner does with a file that did not complete: each block first drops a
-- staging table left by an earlier attempt. That table never holds the only
-- copy of a row: before the EXCHANGE it is a partial copy of the live table,
-- after it the live table already has everything it held.
--
-- Rows written between a block's INSERT ... SELECT and its EXCHANGE land in
-- the old table and are dropped with it. On a database that is receiving
-- writes, scale killswitch-controller and device-inventory to zero while this
-- runs (docs/runbooks/data-maintenance.md, DM-11). On a fresh install both
-- tables are empty and the swap is immediate.

-- ── audit_log ─────────────────────────────────────────────────────────────
DROP TABLE IF EXISTS netsoldier.audit_log_023;

CREATE TABLE netsoldier.audit_log_023
(
    timestamp    DateTime64(3),
    action_id    String,
    from_state   LowCardinality(String),
    to_state     LowCardinality(String),
    actor        String,
    reason       String,
    detection_id String,
    target_mac   String,
    target_ip    String,
    action_type  LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYear(timestamp)
ORDER BY (timestamp, action_id)
TTL toDateTime(timestamp) + INTERVAL 180 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 730 DAY DELETE
SETTINGS storage_policy = 'tiered';

INSERT INTO netsoldier.audit_log_023
    (timestamp, action_id, from_state, to_state, actor, reason, detection_id,
     target_mac, target_ip, action_type)
SELECT timestamp, action_id, from_state, to_state, actor, reason, detection_id,
       target_mac, target_ip, action_type
FROM netsoldier.audit_log;

EXCHANGE TABLES netsoldier.audit_log AND netsoldier.audit_log_023;
DROP TABLE netsoldier.audit_log_023;

-- ── device_events ─────────────────────────────────────────────────────────
DROP TABLE IF EXISTS netsoldier.device_events_023;

CREATE TABLE netsoldier.device_events_023
(
    timestamp    DateTime64(3),
    mac          String,
    ip           String,
    hostname     String,
    vendor       String,
    protocol     LowCardinality(String),
    event_type   LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, mac)
TTL toDateTime(timestamp) + INTERVAL 30 DAY TO VOLUME 'cold',
    toDateTime(timestamp) + INTERVAL 365 DAY DELETE
SETTINGS storage_policy = 'tiered';

INSERT INTO netsoldier.device_events_023
    (timestamp, mac, ip, hostname, vendor, protocol, event_type)
SELECT timestamp, mac, ip, hostname, vendor, protocol, event_type
FROM netsoldier.device_events;

EXCHANGE TABLES netsoldier.device_events AND netsoldier.device_events_023;
DROP TABLE netsoldier.device_events_023;
