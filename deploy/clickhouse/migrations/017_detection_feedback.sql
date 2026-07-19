-- Analyst false-positive feedback (step 118). detection-engine records
-- each verdict here and, on restart, rebuilds active suppressions with
-- argMax(verdict, timestamp) per (matched_ioc, client_ip). An empty
-- client_ip scopes the verdict to the indicator on every device.
-- ReplacingMergeTree collapses re-verdicts of the same (ioc, client, ts).
CREATE TABLE IF NOT EXISTS netsoldier.detection_feedback (
    timestamp   DateTime DEFAULT now(),
    alert_id    String DEFAULT '',
    matched_ioc String,
    client_ip   String DEFAULT '',
    verdict     LowCardinality(String), -- false_positive | confirmed
    reason      String DEFAULT '',
    analyst     String DEFAULT ''
) ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (matched_ioc, client_ip, timestamp)
TTL timestamp + INTERVAL 365 DAY;
