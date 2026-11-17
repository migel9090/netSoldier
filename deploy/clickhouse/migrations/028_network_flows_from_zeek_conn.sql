-- Flow records come from Zeek (step 125.10, audit DP-11).
--
-- network_flows was filled by the Vector aggregator from Suricata EVE flow
-- events that Fluent Bit was meant to forward, and connections by the packet
-- capture that detection-engine no longer has (step 125.9). Neither producer
-- runs in any profile, so both tables stayed empty while the topology map,
-- the device page's connection history and about twenty dashboard panels
-- read them. Zeek's conn.log (zeek_conn, written by the Zeek sidecar) records
-- every connection with its originator and responder, which is what both
-- tables were meant to hold.
--
-- network_flows becomes a view over zeek_conn with the flow vocabulary its
-- readers use: protocol as an IANA number, bytes and packets from the
-- originator's point of view (out = originator to responder). The geo and
-- threat columns migration 019 added were Vector enrichment and have no
-- source any more; they are not part of the view. connections is dropped:
-- every column it had beyond network_flows (the source device's MAC, name,
-- vendor and type, the destination's name) came from the removed capture.
-- device-inventory knows the device, and the destination's name is the TLS
-- server name or HTTP host Zeek logged for the same connection (uid).
--
-- Rows the two tables still hold are dropped with them; no profile wrote
-- any. Export them first (docs/runbooks/data-maintenance.md, DM-11) if a
-- database was filled by hand.
--
-- The view runs with the reader's privileges (ClickHouse 24.3 defaults
-- ordinary views to SQL SECURITY INVOKER), so a reader needs SELECT on
-- zeek_conn as well as on network_flows.
--
-- Safe to re-run from the top: DROP TABLE removes the view too, if an
-- earlier attempt got as far as creating it.
DROP TABLE IF EXISTS netsoldier.connections;
DROP TABLE IF EXISTS netsoldier.network_flows;

CREATE VIEW netsoldier.network_flows AS
SELECT
    timestamp,
    uid,
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    toUInt8(multiIf(proto = 'tcp', 6, proto = 'udp', 17,
                    proto = 'icmp', if(position(dst_ip, ':') > 0, 58, 1), 0)) AS protocol,
    proto,
    service,
    resp_bytes AS bytes_in,
    orig_bytes AS bytes_out,
    resp_pkts AS packets_in,
    orig_pkts AS packets_out,
    duration_ms,
    conn_state,
    local_orig,
    local_resp,
    ingested_at
FROM netsoldier.zeek_conn;
