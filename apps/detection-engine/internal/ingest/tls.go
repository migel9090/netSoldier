package ingest

import (
	"encoding/json"
	"fmt"
	"time"
)

// ZeekSSL tails netsoldier.zeek_ssl (TLS client observations with the
// first-party TLS client fingerprint) for the TLS heuristics of step 110.
type ZeekSSL struct{}

func NewZeekSSL() ZeekSSL { return ZeekSSL{} }

func (ZeekSSL) Name() string { return "zeek_ssl" }

func (ZeekSSL) Columns() string {
	return `toUnixTimestamp(timestamp) AS ts, uid, src_ip, src_port, dst_ip, dst_port,
  server_name, ja3, tls_client_fp`
}

func (ZeekSSL) Identity() string {
	return `timestamp, uid, src_ip, src_port, dst_ip, dst_port, server_name, ja3, tls_client_fp`
}

func (ZeekSSL) Filter() string { return "established = 1" }

type zeekSSLRow struct {
	TS          json.Number `json:"ts"`
	UID         string      `json:"uid"`
	SrcIP       string      `json:"src_ip"`
	SrcPort     json.Number `json:"src_port"`
	DstIP       string      `json:"dst_ip"`
	DstPort     json.Number `json:"dst_port"`
	ServerName  string      `json:"server_name"`
	JA3         string      `json:"ja3"`
	TLSClientFP string      `json:"tls_client_fp"`
}

func (ZeekSSL) Parse(row json.RawMessage) (SensorEvent, error) {
	var r zeekSSLRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, fmt.Errorf("decode zeek ssl: %w", err)
	}

	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, fmt.Errorf("bad ts: %w", err)
	}

	return SensorEvent{
		Sensor:        "zeek",
		Kind:          "tls-client",
		Timestamp:     time.Unix(ts, 0).UTC(),
		FlowID:        r.UID,
		SrcIP:         r.SrcIP,
		SrcPort:       toInt(r.SrcPort),
		DstIP:         r.DstIP,
		DstPort:       toInt(r.DstPort),
		Proto:         "tcp",
		Indicator:     r.TLSClientFP,
		IndicatorType: "tlsfp",
		SNI:           r.ServerName,
		JA3:           r.JA3,
	}, nil
}
