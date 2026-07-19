// Package ingest consumes sensor streams already landed in ClickHouse by
// Vector (Suricata EVE alerts, Zeek Intel framework hits) and normalizes
// them into one SensorEvent model feeding the detection engine's alert
// path. ntopng CE has no export (flow dump is an Enterprise feature), so
// its visibility stays UI-only; flows come from Zeek conn and Suricata EVE.
package ingest

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

// SensorEvent is the unified representation of a detection-grade
// observation from any network sensor.
type SensorEvent struct {
	Sensor        string // "suricata" | "zeek"
	Kind          string // "ids-alert" | "intel-hit"
	Timestamp     time.Time
	FlowID        string // suricata flow_id / zeek uid
	SrcIP         string
	SrcPort       int
	DstIP         string
	DstPort       int
	Proto         string
	Signature     string // rule message or observation point
	Category      string
	Indicator     string // matched IoC value ("" for pure IDS alerts)
	IndicatorType string // normalized: domain, ip, ja3, ja4, cert-sha1, ...
	Severity      string
	Confidence    int
	Source        string // feed / ruleset attribution
	Threat        string

	// TLS client observations (kind "tls-client").
	SNI string
	JA3 string
}

// normalizeIntelType maps Zeek Intel framework type names to the
// project's normalized IoC type vocabulary.
func normalizeIntelType(t string) string {
	switch strings.TrimPrefix(t, "Intel::") {
	case "DOMAIN":
		return "domain"
	case "ADDR", "SUBNET":
		return "ip"
	case "URL":
		return "url"
	case "JA3":
		return "ja3"
	case "JA4":
		return "ja4"
	case "CERT_HASH":
		return "cert-sha256"
	case "FILE_HASH":
		return "sha256"
	default:
		return strings.ToLower(strings.TrimPrefix(t, "Intel::"))
	}
}

// suricataSeverity maps EVE numeric severity (1 = most severe) to the
// shared severity vocabulary.
func suricataSeverity(s int) string {
	switch s {
	case 1:
		return "high"
	case 2:
		return "medium"
	default:
		return "low"
	}
}

// threatIntelContext is the datajson enrichment blob attached to
// dataset-matched Suricata alerts by threat-intel-sync (step 103).
type threatIntelContext struct {
	Source     string `json:"source"`
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`
	Threat     string `json:"threat"`
}

// applyThreatIntel overrides rule-level classification with IoC feed
// context when the alert carries a datajson enrichment payload.
func (e *SensorEvent) applyThreatIntel(raw string) {
	if raw == "" {
		return
	}
	var ti threatIntelContext
	if err := json.Unmarshal([]byte(raw), &ti); err != nil {
		return
	}
	if ti.Severity != "" && ti.Severity != "unknown" {
		e.Severity = ti.Severity
	}
	if ti.Confidence > e.Confidence {
		e.Confidence = ti.Confidence
	}
	if ti.Source != "" {
		e.Source = ti.Source
	}
	if ti.Threat != "" {
		e.Threat = ti.Threat
	}
}

// ToAlert converts a SensorEvent into a detection.Alert, enriching intel
// hits from the live IoC matcher when the indicator is still known.
func ToAlert(ev SensorEvent, m *iocmatch.Matcher) detection.Alert {
	a := detection.Alert{
		Timestamp:  ev.Timestamp,
		Domain:     ev.Indicator,
		ClientIP:   ev.SrcIP,
		MatchedIoC: ev.Indicator,
		Severity:   ev.Severity,
		Source:     ev.Source,
		Confidence: ev.Confidence,
		Threat:     ev.Threat,
	}
	if a.MatchedIoC == "" {
		a.MatchedIoC = ev.Signature
		a.Domain = ev.Signature
	}
	if a.Threat == "" {
		a.Threat = ev.Signature
	}
	if a.Source == "" {
		a.Source = ev.Sensor
	}

	if ev.Kind == "intel-hit" && m != nil {
		if ioc, ok := lookup(m, ev.IndicatorType, ev.Indicator); ok {
			a.Severity = ioc.Severity
			a.Confidence = ioc.Confidence
			if ioc.Source != "" {
				a.Source = ioc.Source
			}
			if ioc.Threat != "" {
				a.Threat = ioc.Threat
			}
			a.MitreID = ioc.MitreID
			a.MitreName = ioc.MitreName
		}
	}
	if a.MitreID == "" {
		a.MitreID, a.MitreName = iocmatch.DeriveMitre(iocmatch.IoC{
			Type: ev.IndicatorType, Threat: ev.Threat,
		})
	}
	if a.Severity == "" {
		a.Severity = "medium"
	}
	return a
}

func lookup(m *iocmatch.Matcher, iocType, value string) (iocmatch.IoC, bool) {
	switch iocType {
	case "domain":
		return m.MatchDomain(value)
	case "ip":
		return m.MatchIP(value)
	case "ja3", "ja4", "md5", "sha256":
		return m.MatchHash(value)
	default:
		return iocmatch.IoC{}, false
	}
}
