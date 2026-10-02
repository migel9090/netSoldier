-- Align detection_feedback retention with the project's privacy promise
-- (step 124).
--
-- The table held verdicts for 365 days while README and COMPLIANCE.md state
-- a 30-day default retention, and each row carries a client_ip — i.e.
-- per-device behavioural data about household members. Suppressions
-- themselves now expire after FEEDBACK_SUPPRESSION_TTL (30 days) in the
-- detection-engine, so a year of history served no operational purpose
-- either.
--
-- 90 days keeps enough trail to answer "who silenced this and when" across a
-- couple of suppression lifetimes, without becoming a long-term record of
-- browsing behaviour.
ALTER TABLE netsoldier.detection_feedback
    MODIFY TTL timestamp + INTERVAL 90 DAY;
