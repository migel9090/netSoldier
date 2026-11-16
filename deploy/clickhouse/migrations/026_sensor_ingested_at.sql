-- Arrival time for the tables detection-engine tails (step 125.19).
--
-- detection-engine read suricata_alerts, zeek_intel, zeek_ssl, ml_beacons and
-- ml_anomalies on a cursor over `timestamp`, the time the sensor says the
-- event happened. A row that lands after a newer one - a retried Vector
-- batch, a sensor whose clock is behind, RITA's last sighting, the end of a
-- scored window - is behind that cursor when it arrives and was never read.
-- The engine now pages on (ingested_at, a hash of the row), so each table
-- gets the time ClickHouse stored the row.
--
-- The value is the server's, taken when the INSERT runs. No writer sends the
-- column: the Vector sinks skip fields that are not columns and none is named
-- ingested_at, and the ML worker names its columns. A late or retried batch
-- therefore gets the time it really arrived.
--
-- Existing rows. Without a value of their own, old parts evaluate the default
-- at read time - every query would see them as just arrived - and a later
-- merge would freeze them all at the merge time, so the whole history would
-- appear to arrive at once. The UPDATE writes the best estimate there is, the
-- event time. mutations_sync = 2 makes this file wait until it is done.
--
-- The minmax index lets the engine's range condition skip granules: the
-- tables are sorted by event time, which arrival time follows closely. The
-- column stays out of the sorting key. Only a column added in the same ALTER
-- could join it, at the end (where it does not help a range), and only
-- without a DEFAULT.
--
-- Safe to re-run from the top after failing part-way: the ADDs are guarded,
-- and the UPDATE then also gives rows written since the first attempt their
-- event time. The engine release that reads ingested_at starts only after
-- this migration has completed, so no reader holds a position among them.
--
-- zeek_conn has its own column from 025.

-- ── suricata_alerts ───────────────────────────────────────────────────────
ALTER TABLE netsoldier.suricata_alerts
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
ALTER TABLE netsoldier.suricata_alerts
    UPDATE ingested_at = toDateTime64(timestamp, 3) WHERE 1
    SETTINGS mutations_sync = 2;
ALTER TABLE netsoldier.suricata_alerts
    ADD INDEX IF NOT EXISTS ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.suricata_alerts
    MATERIALIZE INDEX ingested_at_minmax
    SETTINGS mutations_sync = 2;

-- ── zeek_intel ────────────────────────────────────────────────────────────
ALTER TABLE netsoldier.zeek_intel
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
ALTER TABLE netsoldier.zeek_intel
    UPDATE ingested_at = toDateTime64(timestamp, 3) WHERE 1
    SETTINGS mutations_sync = 2;
ALTER TABLE netsoldier.zeek_intel
    ADD INDEX IF NOT EXISTS ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.zeek_intel
    MATERIALIZE INDEX ingested_at_minmax
    SETTINGS mutations_sync = 2;

-- ── zeek_ssl ──────────────────────────────────────────────────────────────
ALTER TABLE netsoldier.zeek_ssl
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
ALTER TABLE netsoldier.zeek_ssl
    UPDATE ingested_at = toDateTime64(timestamp, 3) WHERE 1
    SETTINGS mutations_sync = 2;
ALTER TABLE netsoldier.zeek_ssl
    ADD INDEX IF NOT EXISTS ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.zeek_ssl
    MATERIALIZE INDEX ingested_at_minmax
    SETTINGS mutations_sync = 2;

-- ── ml_beacons ────────────────────────────────────────────────────────────
ALTER TABLE netsoldier.ml_beacons
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
ALTER TABLE netsoldier.ml_beacons
    UPDATE ingested_at = toDateTime64(timestamp, 3) WHERE 1
    SETTINGS mutations_sync = 2;
ALTER TABLE netsoldier.ml_beacons
    ADD INDEX IF NOT EXISTS ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.ml_beacons
    MATERIALIZE INDEX ingested_at_minmax
    SETTINGS mutations_sync = 2;

-- ── ml_anomalies ──────────────────────────────────────────────────────────
ALTER TABLE netsoldier.ml_anomalies
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);
ALTER TABLE netsoldier.ml_anomalies
    UPDATE ingested_at = toDateTime64(timestamp, 3) WHERE 1
    SETTINGS mutations_sync = 2;
ALTER TABLE netsoldier.ml_anomalies
    ADD INDEX IF NOT EXISTS ingested_at_minmax ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.ml_anomalies
    MATERIALIZE INDEX ingested_at_minmax
    SETTINGS mutations_sync = 2;
