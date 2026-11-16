-- Scope analyst verdicts by signal class (step 125.18).
--
-- A verdict used to be keyed on the indicator alone, so marking one beacon
-- as benign also silenced a later feed match for the same name, and for some
-- sources the "indicator" was as broad as a device's own address. The
-- detection-engine now records which signal class a verdict is about.
--
-- The column joins the sorting key because the table is a
-- ReplacingMergeTree: without it, two verdicts for the same indicator and
-- client in the same second, one per class, would collapse into one row.
-- ClickHouse allows extending the key only with a column added in the same
-- ALTER, and only if that column has no default expression (existing rows
-- get the type's default, the empty string), which is why both changes are
-- one statement and the column declares no DEFAULT.
ALTER TABLE netsoldier.detection_feedback
    ADD COLUMN IF NOT EXISTS signal_class LowCardinality(String) AFTER client_ip,
    MODIFY ORDER BY (matched_ioc, client_ip, timestamp, signal_class);
