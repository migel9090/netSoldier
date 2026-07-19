package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MLBeacons tails netsoldier.ml_beacons (RITA beaconing detections from
// ml-anomaly, step 112). Until step 116 nothing consumed this table; it
// is the "beacon" signal for composite-confidence.
type MLBeacons struct{}

func NewMLBeacons() MLBeacons { return MLBeacons{} }

func (MLBeacons) Name() string { return "ml_beacons" }

func (MLBeacons) Query(since time.Time, limit int) string {
	return fmt.Sprintf(`SELECT toUnixTimestamp(timestamp) AS ts, src_ip, dst_ip,
  dst_domain, beacon_score, connection_count, confidence, severity, beacon_type, tags
FROM ml_beacons WHERE timestamp >= %s
ORDER BY timestamp LIMIT %d FORMAT JSONEachRow`, chTime(since), limit)
}

type mlBeaconRow struct {
	TS              json.Number `json:"ts"`
	SrcIP           string      `json:"src_ip"`
	DstIP           string      `json:"dst_ip"`
	DstDomain       string      `json:"dst_domain"`
	BeaconScore     json.Number `json:"beacon_score"`
	ConnectionCount json.Number `json:"connection_count"`
	Confidence      json.Number `json:"confidence"`
	Severity        string      `json:"severity"`
	BeaconType      string      `json:"beacon_type"`
	Tags            []string    `json:"tags"`
}

func (MLBeacons) Parse(row json.RawMessage) (SensorEvent, string, error) {
	var r mlBeaconRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, "", fmt.Errorf("decode ml beacon: %w", err)
	}
	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, "", fmt.Errorf("bad ts: %w", err)
	}

	threat := "beaconing"
	if r.BeaconType != "" {
		threat = "beaconing (" + r.BeaconType + ")"
	}
	target := r.DstDomain
	if target == "" {
		target = r.DstIP
	}

	ev := SensorEvent{
		Sensor:    "ml-anomaly",
		Kind:      "ml-beacon",
		Timestamp: time.Unix(ts, 0).UTC(),
		SrcIP:     r.SrcIP,
		DstIP:     r.DstIP,
		Signature: fmt.Sprintf("beacon score %s to %s (%s conns)",
			r.BeaconScore.String(), target, r.ConnectionCount.String()),
		Indicator:     target,
		IndicatorType: "beacon",
		Severity:      r.Severity,
		Confidence:    toInt(r.Confidence),
		Source:        "rita",
		Threat:        threat,
	}

	key := fmt.Sprintf("%s/%s/%s", r.SrcIP, r.DstIP, r.TS.String())
	return ev, key, nil
}

// MLAnomalies tails netsoldier.ml_anomalies (Isolation Forest flow
// anomalies, step 113) — the "volumetric" signal.
type MLAnomalies struct{}

func NewMLAnomalies() MLAnomalies { return MLAnomalies{} }

func (MLAnomalies) Name() string { return "ml_anomalies" }

func (MLAnomalies) Query(since time.Time, limit int) string {
	return fmt.Sprintf(`SELECT toUnixTimestamp(timestamp) AS ts,
  toString(window_start) AS window_start, src_ip, anomaly_score, confidence,
  severity, conn_count, bytes_out, dst_fanout, model_version, tags
FROM ml_anomalies WHERE timestamp >= %s
ORDER BY timestamp LIMIT %d FORMAT JSONEachRow`, chTime(since), limit)
}

type mlAnomalyRow struct {
	TS           json.Number `json:"ts"`
	WindowStart  string      `json:"window_start"`
	SrcIP        string      `json:"src_ip"`
	AnomalyScore json.Number `json:"anomaly_score"`
	Confidence   json.Number `json:"confidence"`
	Severity     string      `json:"severity"`
	ConnCount    json.Number `json:"conn_count"`
	BytesOut     json.Number `json:"bytes_out"`
	DstFanout    json.Number `json:"dst_fanout"`
	ModelVersion string      `json:"model_version"`
	Tags         []string    `json:"tags"`
}

func (MLAnomalies) Parse(row json.RawMessage) (SensorEvent, string, error) {
	var r mlAnomalyRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, "", fmt.Errorf("decode ml anomaly: %w", err)
	}
	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, "", fmt.Errorf("bad ts: %w", err)
	}

	// the explanatory tags (upload-heavy, dst-fanout, ...) say what shape
	// of anomaly this was; surface them as the threat description
	shape := "flow anomaly"
	var reasons []string
	for _, t := range r.Tags {
		if t != "anomaly" && t != "iforest" {
			reasons = append(reasons, t)
		}
	}
	if len(reasons) > 0 {
		shape = "flow anomaly: " + strings.Join(reasons, ",")
	}

	ev := SensorEvent{
		Sensor:    "ml-anomaly",
		Kind:      "ml-anomaly",
		Timestamp: time.Unix(ts, 0).UTC(),
		SrcIP:     r.SrcIP,
		Signature: fmt.Sprintf("anomaly score %s window %s (model %s)",
			r.AnomalyScore.String(), r.WindowStart, r.ModelVersion),
		Indicator:     r.SrcIP,
		IndicatorType: "flow-window",
		Severity:      r.Severity,
		Confidence:    toInt(r.Confidence),
		Source:        "iforest",
		Threat:        shape,
	}

	key := fmt.Sprintf("%s/%s", r.SrcIP, r.WindowStart)
	return ev, key, nil
}
