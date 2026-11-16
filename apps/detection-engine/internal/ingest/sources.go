package ingest

import (
	"encoding/json"
	"fmt"
	"time"
)

// ZeekIntel tails netsoldier.zeek_intel (Intel framework hits).
type ZeekIntel struct{}

func NewZeekIntel() ZeekIntel { return ZeekIntel{} }

func (ZeekIntel) Name() string { return "zeek_intel" }

func (ZeekIntel) Columns() string {
	return `toUnixTimestamp(timestamp) AS ts, uid, src_ip, src_port, dst_ip, dst_port,
  indicator, indicator_type, seen_where, sources`
}

func (ZeekIntel) Identity() string {
	return `timestamp, uid, src_ip, src_port, dst_ip, dst_port, indicator, indicator_type, seen_where, sources`
}

func (ZeekIntel) Filter() string { return "" }

type zeekIntelRow struct {
	TS            json.Number `json:"ts"`
	UID           string      `json:"uid"`
	SrcIP         string      `json:"src_ip"`
	SrcPort       json.Number `json:"src_port"`
	DstIP         string      `json:"dst_ip"`
	DstPort       json.Number `json:"dst_port"`
	Indicator     string      `json:"indicator"`
	IndicatorType string      `json:"indicator_type"`
	SeenWhere     string      `json:"seen_where"`
	Sources       []string    `json:"sources"`
}

func (ZeekIntel) Parse(row json.RawMessage) (SensorEvent, error) {
	var r zeekIntelRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, fmt.Errorf("decode zeek intel: %w", err)
	}

	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, fmt.Errorf("bad ts: %w", err)
	}

	source := "zeek-intel"
	if len(r.Sources) > 0 {
		source = r.Sources[0]
	}

	return SensorEvent{
		Sensor:        "zeek",
		Kind:          "intel-hit",
		Timestamp:     time.Unix(ts, 0).UTC(),
		FlowID:        r.UID,
		SrcIP:         r.SrcIP,
		SrcPort:       toInt(r.SrcPort),
		DstIP:         r.DstIP,
		DstPort:       toInt(r.DstPort),
		Proto:         "tcp",
		Signature:     r.SeenWhere,
		Indicator:     r.Indicator,
		IndicatorType: normalizeIntelType(r.IndicatorType),
		Source:        source,
	}, nil
}

func toInt(n json.Number) int {
	v, _ := n.Int64()
	return int(v)
}
