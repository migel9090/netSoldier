CREATE TABLE IF NOT EXISTS netsoldier.suricata_alerts (
    timestamp    DateTime,
    flow_id      UInt64,
    src_ip       String,
    src_port     UInt16,
    dest_ip      String,
    dest_port    UInt16,
    proto        LowCardinality(String),
    alert_action LowCardinality(String),
    alert_gid    UInt32,
    alert_signature_id UInt32,
    alert_rev    UInt32,
    alert_signature    String,
    alert_category     LowCardinality(String),
    alert_severity     UInt8,
    app_proto    LowCardinality(String),
    flow_pkts_toserver  UInt32 DEFAULT 0,
    flow_pkts_toclient  UInt32 DEFAULT 0,
    flow_bytes_toserver UInt64 DEFAULT 0,
    flow_bytes_toclient UInt64 DEFAULT 0,
    threat_intel String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (timestamp, alert_signature_id, src_ip)
TTL timestamp + INTERVAL 90 DAY;
ALTER TABLE netsoldier.suricata_alerts
    ADD COLUMN IF NOT EXISTS threat_intel String DEFAULT '';
CREATE TABLE IF NOT EXISTS netsoldier.suricata_dns (
    timestamp    DateTime,
    flow_id      UInt64,
    src_ip       String,
    src_port     UInt16,
    dest_ip      String,
    dest_port    UInt16,
    proto        LowCardinality(String),
    dns_type     LowCardinality(String),
    dns_rrtype   LowCardinality(String),
    dns_rrname   String,
    dns_rdata    String,
    dns_rcode    LowCardinality(String),
    dns_id       UInt16
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, dns_rrname)
TTL timestamp + INTERVAL 30 DAY;
CREATE TABLE IF NOT EXISTS netsoldier.suricata_tls (
    timestamp    DateTime,
    flow_id      UInt64,
    src_ip       String,
    src_port     UInt16,
    dest_ip      String,
    dest_port    UInt16,
    proto        LowCardinality(String),
    tls_version  LowCardinality(String),
    tls_sni      String,
    tls_subject  String,
    tls_issuerdn String,
    tls_serial   String,
    tls_ja3_hash  String,
    tls_ja3s_hash String
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, tls_sni)
TTL timestamp + INTERVAL 30 DAY;
