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
//
// timestamp is RITA's last sighting of the beacon, which can be well behind
// the time the row is written; only arrival order reads every row.
type MLBeacons struct{}

func NewMLBeacons() MLBeacons { return MLBeacons{} }

func (MLBeacons) Name() string { return "ml_beacons" }

func (MLBeacons) Columns() string {
	return `toUnixTimestamp(timestamp) AS ts, src_ip, dst_ip, dst_domain, beacon_score,
  connection_count, confidence, severity, beacon_type, tags`
}

// Identity includes dst_domain: SNI beacons have no destination address, so
// two from one device at the same time differ only by name.
func (MLBeacons) Identity() string {
	return `timestamp, src_ip, dst_ip, dst_domain, beacon_score, connection_count, confidence,
  severity, beacon_type, tags`
}

func (MLBeacons) Filter() string { return "" }

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

func (MLBeacons) Parse(row json.RawMessage) (SensorEvent, error) {
	var r mlBeaconRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, fmt.Errorf("decode ml beacon: %w", err)
	}
	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, fmt.Errorf("bad ts: %w", err)
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
		DstDomain:     r.DstDomain,
		Severity:      r.Severity,
		Confidence:    toInt(r.Confidence),
		Source:        "rita",
		Threat:        threat,
	}
	return ev, nil
}

// MLAnomalies tails netsoldier.ml_anomalies (Isolation Forest flow
// anomalies, step 113) — the "volumetric" signal. timestamp is the end of
// the scored window, and the row is written after the window closed.
type MLAnomalies struct{}

func NewMLAnomalies() MLAnomalies { return MLAnomalies{} }

func (MLAnomalies) Name() string { return "ml_anomalies" }

func (MLAnomalies) Columns() string {
	return `toUnixTimestamp(timestamp) AS ts, toString(window_start) AS window_start_s, src_ip,
  anomaly_score, confidence, severity, conn_count, bytes_out, dst_fanout, model_version, tags`
}

func (MLAnomalies) Identity() string {
	return `timestamp, window_start, src_ip, anomaly_score, confidence, severity, conn_count,
  bytes_out, dst_fanout, model_version, tags`
}

func (MLAnomalies) Filter() string { return "" }

type mlAnomalyRow struct {
	TS           json.Number `json:"ts"`
	WindowStart  string      `json:"window_start_s"`
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

func (MLAnomalies) Parse(row json.RawMessage) (SensorEvent, error) {
	var r mlAnomalyRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, fmt.Errorf("decode ml anomaly: %w", err)
	}
	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, fmt.Errorf("bad ts: %w", err)
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
	return ev, nil
}
