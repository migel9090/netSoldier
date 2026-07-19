CREATE TABLE IF NOT EXISTS netsoldier.zeek_conn (
    timestamp   DateTime,
    uid         String,
    src_ip      String,
    src_port    UInt16,
    dst_ip      String,
    dst_port    UInt16,
    proto       LowCardinality(String),
    service     LowCardinality(String),
    duration_ms UInt64,
    orig_bytes  UInt64,
    resp_bytes  UInt64,
    conn_state  LowCardinality(String),
    local_orig  UInt8,
    local_resp  UInt8,
    history     String,
    orig_pkts   UInt64,
    resp_pkts   UInt64
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;
CREATE TABLE IF NOT EXISTS netsoldier.zeek_dns (
    timestamp  DateTime,
    uid        String,
    src_ip     String,
    src_port   UInt16,
    dst_ip     String,
    dst_port   UInt16,
    proto      LowCardinality(String),
    query      String,
    qtype_name LowCardinality(String),
    rcode_name LowCardinality(String),
    answers    Array(String),
    rejected   UInt8
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, query)
TTL timestamp + INTERVAL 30 DAY;
CREATE TABLE IF NOT EXISTS netsoldier.zeek_ssl (
    timestamp   DateTime,
    uid         String,
    src_ip      String,
    src_port    UInt16,
    dst_ip      String,
    dst_port    UInt16,
    version     LowCardinality(String),
    cipher      LowCardinality(String),
    curve       LowCardinality(String),
    server_name String,
    resumed     UInt8,
    established UInt8,
    subject     String,
    issuer      String,
    ja3           String DEFAULT '',
    ja3s          String DEFAULT '',
    tls_client_fp String DEFAULT ''
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, server_name)
TTL timestamp + INTERVAL 30 DAY;
ALTER TABLE netsoldier.zeek_ssl ADD COLUMN IF NOT EXISTS ja3 String DEFAULT '';
ALTER TABLE netsoldier.zeek_ssl ADD COLUMN IF NOT EXISTS ja3s String DEFAULT '';
ALTER TABLE netsoldier.zeek_ssl ADD COLUMN IF NOT EXISTS tls_client_fp String DEFAULT '';
CREATE TABLE IF NOT EXISTS netsoldier.zeek_x509 (
    timestamp        DateTime,
    fingerprint      String,
    serial           String,
    subject          String,
    issuer           String,
    not_valid_before DateTime,
    not_valid_after  DateTime,
    key_alg          LowCardinality(String),
    key_length       UInt16,
    san_dns          Array(String)
) ENGINE = MergeTree()
ORDER BY (timestamp, fingerprint)
TTL timestamp + INTERVAL 30 DAY;
CREATE TABLE IF NOT EXISTS netsoldier.zeek_http (
    timestamp         DateTime,
    uid               String,
    src_ip            String,
    src_port          UInt16,
    dst_ip            String,
    dst_port          UInt16,
    method            LowCardinality(String),
    host              String,
    uri               String,
    referrer          String,
    user_agent        String,
    status_code       UInt16,
    request_body_len  UInt64,
    response_body_len UInt64
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, host)
TTL timestamp + INTERVAL 30 DAY;
