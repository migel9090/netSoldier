-- zeek_conn.ingested_at: when a row reached ClickHouse (step 125.23).
--
-- A conn.log row is written when the connection ends but carries its start
-- time, so `timestamp` cannot tell a reader which rows are new: a 44-minute
-- upload shows up 44 minutes "in the past". ml-anomaly's flow cursor runs on
-- this server-stamped column instead, which is what lets it score a long
-- flow exactly once and neither re-score nor skip a window after a restart.
ALTER TABLE netsoldier.zeek_conn
    ADD COLUMN IF NOT EXISTS ingested_at DateTime64(3) DEFAULT now64(3);

-- Rows that existed before the column would evaluate the DEFAULT at read time
-- (the time of each query), and a later merge would freeze them at the merge
-- time: a whole history arriving "now". Give them their approximate arrival
-- instead, the end of the flow. The runner applies this file once.
ALTER TABLE netsoldier.zeek_conn
    UPDATE ingested_at = timestamp + toIntervalSecond(intDiv(duration_ms, 1000)) WHERE 1
    SETTINGS mutations_sync = 2;

-- The cursor filters on ingested_at, which is not in the sorting key.
ALTER TABLE netsoldier.zeek_conn
    ADD INDEX IF NOT EXISTS idx_ingested_at ingested_at TYPE minmax GRANULARITY 1;
ALTER TABLE netsoldier.zeek_conn
    MATERIALIZE INDEX idx_ingested_at SETTINGS mutations_sync = 2;
