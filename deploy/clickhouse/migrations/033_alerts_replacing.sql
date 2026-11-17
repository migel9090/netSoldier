-- alerts collapses repeated copies again (step 125.10).
--
-- 005 created alerts as a ReplacingMergeTree keyed on (timestamp, id), so a
-- row written twice is kept once. 020 rebuilt the table to partition it and
-- gave the replacement a plain MergeTree, so that stopped. It matters now
-- that detection-engine copies its alert history here: a batch it writes
-- again after a crash between the insert and saving its position would
-- otherwise count every alert in it twice on the dashboards. This rebuild
-- restores the engine and keeps everything else 020 and 030 set: monthly
-- partitions, the tiered storage policy and its TTL, the columns.
--
-- The rebuild copies into a staging table with the same structure, swaps the
-- two (EXCHANGE TABLES is atomic), then copies over every alert the old
-- table received during the copy (by id, which is unique per detection), and
-- drops the old table.
--
-- Safe to re-run from the top after failing part-way: the staging table of
-- an earlier attempt is dropped first. Before the swap it holds a partial
-- copy; after it the live table already holds what the copy did. Only a
-- failure between the swap and the catch-up insert, with detection-engine
-- writing in those seconds, can lose what it wrote then.
DROP TABLE IF EXISTS netsoldier.alerts_033;

CREATE TABLE netsoldier.alerts_033 AS netsoldier.alerts
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, id)
TTL timestamp + INTERVAL 90 DAY TO VOLUME 'cold', timestamp + INTERVAL 365 DAY DELETE
SETTINGS storage_policy = 'tiered';

INSERT INTO netsoldier.alerts_033 SELECT * FROM netsoldier.alerts;

EXCHANGE TABLES netsoldier.alerts AND netsoldier.alerts_033;

INSERT INTO netsoldier.alerts
SELECT * FROM netsoldier.alerts_033
WHERE id NOT IN (SELECT id FROM netsoldier.alerts);

DROP TABLE netsoldier.alerts_033;
