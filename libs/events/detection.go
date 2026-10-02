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

// Signal classes label where a detection came from. They live in the shared
// contract (not just in the detection-engine) because the killswitch policy
// has to tell corroborating evidence apart by KIND, not just by count: a
// feed/signature hit is externally attested "known bad", while beaconing,
// volumetric and TLS signals are local heuristics. Auto-enforcement keys off
// that distinction (see IsKnownBadSignal).
const (
	SignalIoC        = "ioc"           // domain/IP/hash match from a feed
	SignalIDS        = "ids-signature" // Suricata rule hit
	SignalTLS        = "tls"           // TLS fingerprint/SNI heuristic
	SignalBeacon     = "beacon"        // RITA beaconing
	SignalVolumetric = "volumetric"    // Isolation Forest flow anomaly
	SignalComposite  = "composite"     // combined output
)

// IsKnownBadSignal reports whether a signal class represents an externally
// attested known-bad indicator (a threat-feed match or an IDS signature) as
// opposed to a locally derived heuristic.
func IsKnownBadSignal(class string) bool {
	return class == SignalIoC || class == SignalIDS
}

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
	IoCType    string `json:"ioc_type"` // "domain", "ip", "ja3", "tlsfp", "md5", "sha256"

	// Who triggered it.
	ClientIP   string `json:"client_ip"`
	ClientMAC  string `json:"client_mac,omitempty"`
	ClientName string `json:"client_name,omitempty"`

	// Classification.
	Severity   string `json:"severity"`   // SeverityCritical..SeverityLow
	Confidence int    `json:"confidence"` // 0-100
	Source     string `json:"source"`     // IoC source feed name
	Threat     string `json:"threat"`     // malware family / threat name

	// MITRE ATT&CK mapping.
	MitreID   string `json:"mitre_id,omitempty"`
	MitreName string `json:"mitre_name,omitempty"`

	// Context.
	QueryType string   `json:"query_type,omitempty"` // DNS query type: "A", "AAAA", etc.
	Tags      []string `json:"tags,omitempty"`

	// Composite-confidence context (step 116). Additive optional fields:
	// when a detection is the product of several corroborating signals
	// (signature + beaconing + volumetric + TLS + IoC), Signals lists the
	// contributing signal classes and SignalCount their number. Confidence
	// above already carries the combined (noisy-OR) value.
	//
	// SignalClass names the class of a SINGLE-signal detection. Composite
	// detections set it to SignalComposite and populate Signals instead.
	// It is load-bearing for enforcement: without it the killswitch cannot
	// tell a feed match from a heuristic (step 124).
	SignalClass string   `json:"signal_class,omitempty"`
	Signals     []string `json:"signals,omitempty"`
	SignalCount int      `json:"signal_count,omitempty"`
}

// KnownBadSignals returns the known-bad signal classes carried by the event.
// A single-signal detection is described by SignalClass; a composite carries
// its contributors in Signals. An event with neither (a producer that predates
// step 124, or one that forgot to label itself) returns nil — callers must
// treat that as "no attested known-bad evidence" and never as a free pass.
func (e DetectionEvent) KnownBadSignals() []string {
	var out []string
	if IsKnownBadSignal(e.SignalClass) {
		out = append(out, e.SignalClass)
	}
	for _, s := range e.Signals {
		if IsKnownBadSignal(s) && !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// HasKnownBadSignal reports whether the event is backed by at least one
// externally attested known-bad indicator.
func (e DetectionEvent) HasKnownBadSignal() bool {
	return len(e.KnownBadSignals()) > 0
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
