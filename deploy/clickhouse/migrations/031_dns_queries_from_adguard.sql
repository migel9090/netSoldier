-- dns_queries comes from AdGuard's query log (step 125.10, audit DP-11).
--
-- The table was meant to be filled by the Vector aggregator from Suricata
-- DNS events that never reached it. detection-engine already reads every
-- query AdGuard answers, to check it against the indicators; it now writes
-- each one here as well, in batches, unless DNS_QUERY_EXPORT=off. AdGuard
-- sees what Suricata cannot: which device asked (the resolver's client, not
-- a NAT address), whether the answer was blocked and why, and how long the
-- answer took.
--
-- reason is AdGuard's filtering verdict (NotFilteredNotFound,
-- FilteredBlackList, Rewrite, ...); blocked is 1 for the verdicts that
-- stopped the answer.
--
-- Retention: 30 days, then deleted. This is every DNS lookup of every
-- device in the household - its browsing history - so it gets the 30-day
-- retention the project promises for per-device data (README,
-- docs/threat-model.md I-01) and is not kept on the cold tier: 018 and 020
-- moved it there after 30 days and deleted it after 365. A longer horizon is
-- one statement for the operator:
--   ALTER TABLE netsoldier.dns_queries MODIFY TTL timestamp + INTERVAL <n> DAY DELETE
--
-- Safe on a table with rows and to re-run: the ADD is guarded, MODIFY TTL
-- replaces the rule (existing parts past the horizon are deleted by the
-- server in the background).
ALTER TABLE netsoldier.dns_queries
    ADD COLUMN IF NOT EXISTS reason LowCardinality(String) DEFAULT '';

ALTER TABLE netsoldier.dns_queries
    MODIFY TTL timestamp + INTERVAL 30 DAY DELETE;
