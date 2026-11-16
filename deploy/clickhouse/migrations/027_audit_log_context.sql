-- What an enforcement decision was about (step 125.17).
--
-- An audit row said which action changed state and who changed it, but not
-- what was blocked, which policy rule decided it or what the detection was.
-- Answering "why was this device cut off" meant joining against data that
-- may already have expired. The killswitch has these three values on every
-- entry and already sends them; until now ClickHouse had nowhere to put them
-- and they were skipped on insert.
ALTER TABLE netsoldier.audit_log
    ADD COLUMN IF NOT EXISTS blocked_domain String DEFAULT '',
    ADD COLUMN IF NOT EXISTS policy_rule String DEFAULT '',
    ADD COLUMN IF NOT EXISTS detection_summary String DEFAULT '';
