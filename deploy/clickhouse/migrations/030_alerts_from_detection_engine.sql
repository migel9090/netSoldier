-- alerts is written by detection-engine (step 125.10, audit DP-11).
--
-- The table was meant to be filled by the Vector aggregator with Suricata
-- alerts it never received, so the device page's alert tab and the alert
-- panels stayed empty. detection-engine is where every detection is made:
-- DNS indicator matches, Suricata and Zeek Intel hits, beacons, flow
-- anomalies and the composites built from them. It now copies each alert it
-- records in its local history here, in order, retrying until ClickHouse
-- accepts it.
--
-- The columns below carry what an alert is about beyond the original
-- schema. `timestamp` is when the engine made the detection (its own clock:
-- the partition and the retention follow it, and a sensor cannot move a row
-- out of either), observed_at is the time the input record gave. id is the
-- detection id; a copy repeated after a crash has the same (timestamp, id),
-- which the ReplacingMergeTree that 033 restores collapses.
--
-- acknowledged and rdns stay: nothing sets them any more (there is no
-- acknowledgement in netSoldier; suppressed is the analyst's verdict), and
-- existing rows keep their values.
--
-- Only ADD COLUMN IF NOT EXISTS: safe on a table with rows, and to re-run.
ALTER TABLE netsoldier.alerts
    ADD COLUMN IF NOT EXISTS observed_at DateTime64(3) DEFAULT toDateTime64(timestamp, 3),
    ADD COLUMN IF NOT EXISTS summary String DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_mac String DEFAULT '',
    ADD COLUMN IF NOT EXISTS client_name String DEFAULT '',
    ADD COLUMN IF NOT EXISTS ioc_type LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS signal_class LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS confidence UInt8 DEFAULT 0,
    ADD COLUMN IF NOT EXISTS target_type LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS target_value String DEFAULT '',
    ADD COLUMN IF NOT EXISTS threat String DEFAULT '',
    ADD COLUMN IF NOT EXISTS mitre_id LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS suppressed UInt8 DEFAULT 0;
