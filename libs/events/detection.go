// Package events defines versioned event schemas shared across netSoldier
// services. All producers and consumers of detection events MUST use these
// types to ensure wire compatibility.
package events

import "time"

// DetectionSchemaVersion is the current version of the DetectionEvent schema.
// Bump on any breaking field change (rename, type change, removal).
// Additive changes (new optional fields) do NOT require a version bump.
const DetectionSchemaVersion = "1.0"

// Severity constants.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// DetectionEvent is the canonical detection event produced by the
// detection-engine and consumed by killswitch-controller, web-ui,
// ClickHouse, and webhook receivers.
type DetectionEvent struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`

	// What was detected.
	Domain     string `json:"domain"`
	MatchedIoC string `json:"matched_ioc"`
	IoCType    string `json:"ioc_type"` // "domain", "ip", "ja3", "ja4", "md5", "sha256"

	// Who triggered it.
	ClientIP   string `json:"client_ip"`
	ClientMAC  string `json:"client_mac,omitempty"`
	ClientName string `json:"client_name,omitempty"`

	// Classification.
	Severity   string `json:"severity"`   // SeverityCritical..SeverityLow
	Confidence int    `json:"confidence"`  // 0-100
	Source     string `json:"source"`      // IoC source feed name
	Threat     string `json:"threat"`      // malware family / threat name

	// MITRE ATT&CK mapping.
	MitreID   string `json:"mitre_id,omitempty"`
	MitreName string `json:"mitre_name,omitempty"`

	// Context.
	QueryType string   `json:"query_type,omitempty"` // DNS query type: "A", "AAAA", etc.
	Tags      []string `json:"tags,omitempty"`
}

// IsSevereEnoughForAuto returns true if the event meets the threshold
// for automatic enforcement (no human approval required).
func (e DetectionEvent) IsSevereEnoughForAuto() bool {
	return (e.Severity == SeverityCritical || e.Severity == SeverityHigh) && e.Confidence >= 80
}
