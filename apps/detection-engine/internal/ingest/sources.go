package ingest

import (
	"encoding/json"
	"fmt"
	"time"
)

// SuricataAlerts tails netsoldier.suricata_alerts (EVE alert events).
type SuricataAlerts struct{}

func NewSuricataAlerts() SuricataAlerts { return SuricataAlerts{} }

func (SuricataAlerts) Name() string { return "suricata_alerts" }

func (SuricataAlerts) Query(since time.Time, limit int) string {
	return fmt.Sprintf(`SELECT toUnixTimestamp(timestamp) AS ts, flow_id, src_ip, src_port,
  dest_ip, dest_port, proto, alert_signature, alert_category, alert_severity,
  alert_signature_id, threat_intel
FROM suricata_alerts WHERE timestamp >= %s
ORDER BY timestamp LIMIT %d FORMAT JSONEachRow`, chTime(since), limit)
}

type suricataAlertRow struct {
	TS               json.Number `json:"ts"`
	FlowID           json.Number `json:"flow_id"`
	SrcIP            string      `json:"src_ip"`
	SrcPort          json.Number `json:"src_port"`
	DestIP           string      `json:"dest_ip"`
	DestPort         json.Number `json:"dest_port"`
	Proto            string      `json:"proto"`
	AlertSignature   string      `json:"alert_signature"`
	AlertCategory    string      `json:"alert_category"`
	AlertSeverity    json.Number `json:"alert_severity"`
	AlertSignatureID json.Number `json:"alert_signature_id"`
	ThreatIntel      string      `json:"threat_intel"`
}

func (SuricataAlerts) Parse(row json.RawMessage) (SensorEvent, string, error) {
	var r suricataAlertRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, "", fmt.Errorf("decode suricata alert: %w", err)
	}

	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, "", fmt.Errorf("bad ts: %w", err)
	}
	sev, _ := r.AlertSeverity.Int64()

	ev := SensorEvent{
		Sensor:    "suricata",
		Kind:      "ids-alert",
		Timestamp: time.Unix(ts, 0).UTC(),
		FlowID:    r.FlowID.String(),
		SrcIP:     r.SrcIP,
		SrcPort:   toInt(r.SrcPort),
		DstIP:     r.DestIP,
		DstPort:   toInt(r.DestPort),
		Proto:     r.Proto,
		Signature: r.AlertSignature,
		Category:  r.AlertCategory,
		Severity:  suricataSeverity(int(sev)),
		Source:    "et-open",
	}
	ev.applyThreatIntel(r.ThreatIntel)

	key := fmt.Sprintf("%s/%s/%s", r.FlowID.String(), r.AlertSignatureID.String(), r.TS.String())
	return ev, key, nil
}

// ZeekIntel tails netsoldier.zeek_intel (Intel framework hits).
type ZeekIntel struct{}

func NewZeekIntel() ZeekIntel { return ZeekIntel{} }

func (ZeekIntel) Name() string { return "zeek_intel" }

func (ZeekIntel) Query(since time.Time, limit int) string {
	return fmt.Sprintf(`SELECT toUnixTimestamp(timestamp) AS ts, uid, src_ip, src_port,
  dst_ip, dst_port, indicator, indicator_type, seen_where, sources
FROM zeek_intel WHERE timestamp >= %s
ORDER BY timestamp LIMIT %d FORMAT JSONEachRow`, chTime(since), limit)
}

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

func (ZeekIntel) Parse(row json.RawMessage) (SensorEvent, string, error) {
	var r zeekIntelRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, "", fmt.Errorf("decode zeek intel: %w", err)
	}

	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, "", fmt.Errorf("bad ts: %w", err)
	}

	source := "zeek-intel"
	if len(r.Sources) > 0 {
		source = r.Sources[0]
	}

	ev := SensorEvent{
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
	}

	key := fmt.Sprintf("%s/%s/%s", r.UID, r.Indicator, r.TS.String())
	return ev, key, nil
}

func toInt(n json.Number) int {
	v, _ := n.Int64()
	return int(v)
}
