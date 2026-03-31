CREATE TABLE IF NOT EXISTS netsoldier.network_flows (
    timestamp    DateTime,
    src_ip       String,
    src_port     UInt16,
    dst_ip       String,
    dst_port     UInt16,
    protocol     UInt8,
    bytes_in     UInt64,
    bytes_out    UInt64,
    packets_in   UInt32,
    packets_out  UInt32,
    duration_ms  UInt32,
    tcp_flags    UInt8,
    vlan_id      UInt16
) ENGINE = MergeTree()
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 30 DAY;
