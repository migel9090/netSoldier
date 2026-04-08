CREATE TABLE IF NOT EXISTS netsoldier.connections (
    timestamp       DateTime,
    src_mac         String,
    src_hostname    String,
    src_vendor      String,
    src_os          String,
    src_device_type String,
    src_ip          String,
    src_port        UInt16,
    dst_ip          String,
    dst_domain      String,
    dst_port        UInt16,
    protocol        UInt8,
    bytes_in        UInt64,
    bytes_out       UInt64,
    packets_in      UInt32,
    packets_out     UInt32,
    duration_ms     UInt32,
    tcp_flags       UInt8,
    vlan_id         UInt16
) ENGINE = MergeTree()
ORDER BY (timestamp, src_mac, dst_ip)
TTL timestamp + INTERVAL 30 DAY;
