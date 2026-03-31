CREATE TABLE IF NOT EXISTS netsoldier.devices (
    mac          String,
    ip           String,
    hostname     String,
    fingerprint  String,
    vendor_class String,
    vendor       String,
    os           String,
    device_type  String,
    stable_id    String,
    labels       Array(String),
    first_seen   DateTime,
    last_seen    DateTime,
    updated_at   DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(updated_at)
ORDER BY mac;

CREATE TABLE IF NOT EXISTS netsoldier.device_events (
    timestamp    DateTime,
    mac          String,
    ip           String,
    hostname     String,
    vendor       String,
    protocol     LowCardinality(String),
    event_type   LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, mac)
TTL timestamp + INTERVAL 30 DAY;
