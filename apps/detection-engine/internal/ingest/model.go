// Package ingest consumes sensor streams already landed in ClickHouse by
// Vector (Suricata EVE alerts, Zeek Intel framework hits) and normalizes
// them into one SensorEvent model feeding the detection engine's alert
// path. ntopng CE has no export (flow dump is an Enterprise feature), so
// its visibility stays UI-only; flows come from Zeek conn and Suricata EVE.
package ingest

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
)

// SensorEvent is the unified representation of a detection-grade
// observation from any network sensor.
type SensorEvent struct {
	Sensor string // "suricata" | "zeek" | "ml-anomaly"
	// Kind is "ids-alert", "ids-dataset" (a Suricata rule that fired on a
	// feed indicator), "intel-hit", "tls-client", "ml-beacon" or
	// "ml-anomaly".
	Kind      string
	Timestamp time.Time
	FlowID    string // suricata flow_id / zeek uid
	// SrcIP is the client: for Suricata alerts the household's side of the
	// flow, which is not always the packet's source.
	SrcIP         string
	SrcPort       int
	DstIP         string
	DstPort       int
	Proto         string
	Signature     string // rule message or observation point
	SignatureID   string // IDS rule SID (kind "ids-alert")
	Category      string
	Indicator     string // matched IoC value ("" for pure IDS alerts)
	IndicatorType string // normalized: domain, ip, ja3, tlsfp, cert-sha1, ...
	Severity      string
	Confidence    int
	Source        string // feed / ruleset attribution
	Threat        string

	// DstDomain is the destination name a beacon was observed to, when the
	// sensor knows one (kind "ml-beacon").
	DstDomain string

	// TLS client observations (kind "tls-client").
	SNI string
	JA3 string

	// Origin and RowKey identify the row the event came from (the table and
	// the row's identity hash), so reading the same row again is recognised.
	Origin string
	RowKey string
}

// Record names the row for the pipeline's ledger of handled records, or ""
// when the event does not come from a stored row.
func (e SensorEvent) Record() string {
	if e.RowKey == "" {
		return ""
	}
	return detection.Record(e.Origin, e.RowKey)
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
	case "TLSFP":
		return "tlsfp"
	case "CERT_HASH":
		return "cert-sha256"
	case "FILE_HASH":
		return "sha256"
	default:
		return strings.ToLower(strings.TrimPrefix(t, "Intel::"))
	}
}

// ToAlert converts a SensorEvent into a detection.Alert, enriching intel
// hits from the live IoC matcher when the indicator is still known.
//
// Each sensor kind says something different, so each is mapped on its own
// terms: the summary describes what was seen, Domain carries only a DNS name
// that was really observed, the one signal carries this observation's own
// confidence and the indicator it attests, and Target is set only when there
// is something concrete to act on — the feed's domain or address for an
// intel hit, the observed destination for a heuristic. A Suricata rule hit
// attests a rule, not a destination, so it carries no target; neither does a
// volumetric anomaly, which is about the device itself.
//
// A Suricata rule that fired because its dataset held a feed indicator is
// mapped like a Zeek Intel hit: class ioc, the indicator, the feed's
// confidence. Labelled as a signature it counted as independent
// corroboration of the very feed match AdGuard had already reported, and one
// confidence-75 indicator became a 94/critical composite.
func ToAlert(ev SensorEvent, m *iocmatch.Matcher) detection.Alert {
	a := detection.Alert{
		Record:      ev.Record(),
		Timestamp:   ev.Timestamp,
		ClientIP:    canonicalOrRaw(ev.SrcIP),
		Severity:    ev.Severity,
		Source:      ev.Source,
		Confidence:  ev.Confidence,
		Threat:      ev.Threat,
		SignalClass: signalClass(ev.Kind),
	}
	if a.Threat == "" {
		a.Threat = ev.Signature
	}
	if a.Source == "" {
		a.Source = ev.Sensor
	}

	if (ev.Kind == "intel-hit" || ev.Kind == "ids-dataset") && m != nil {
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
	a.Confidence = detection.ClampConfidence(a.Confidence)

	sig := events.Signal{Class: a.SignalClass, Confidence: a.Confidence, Source: a.Source}
	switch ev.Kind {
	case "ids-alert":
		if ev.SignatureID != "" && ev.SignatureID != "0" {
			sig.Indicator, sig.IndicatorType = ev.SignatureID, events.IndicatorSID
		}
		a.Summary = fmt.Sprintf("IDS signature %q (%s)", ev.Signature, between(ev))
	case "ids-dataset":
		sig.Indicator, sig.IndicatorType = feedIndicator(&a, ev)
		listed := "a listed indicator"
		if sig.Indicator != "" {
			listed = sig.IndicatorType + " " + sig.Indicator
		}
		a.Summary = fmt.Sprintf("Suricata rule %q matched %s listed by %s (%s)",
			ev.Signature, listed, a.Source, between(ev))
	case "intel-hit":
		sig.Indicator, sig.IndicatorType = feedIndicator(&a, ev)
		a.Summary = fmt.Sprintf("Zeek Intel: %s %s listed by %s, seen in %s (%s)",
			ev.IndicatorType, sig.Indicator, a.Source, ev.Signature, flow(ev))
	case "ml-beacon":
		if d, ok := events.CanonicalDomain(ev.DstDomain); ok {
			sig.Indicator, sig.IndicatorType = d, events.IndicatorDomain
			a.Domain = d
			a.Target = &events.Target{Type: events.TargetDomain, Value: d}
		} else if ip, ok := events.CanonicalIP(ev.DstIP); ok {
			sig.Indicator, sig.IndicatorType = ip, events.IndicatorIP
			a.Target = &events.Target{Type: events.TargetIP, Value: ip}
		}
		a.Summary = "Beaconing from " + a.ClientIP + ": " + ev.Signature
	case "ml-anomaly":
		a.Summary = "Volumetric anomaly for " + a.ClientIP + ": " + ev.Signature
		if ev.Threat != "" {
			a.Summary += " — " + ev.Threat
		}
	default:
		a.Summary = fmt.Sprintf("%s %s: %s", ev.Sensor, ev.Kind, firstNonEmpty(ev.Signature, ev.Indicator))
	}
	a.Signals = []events.Signal{sig}
	a.MatchedIoC, a.IoCType = sig.Indicator, sig.IndicatorType

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

// feedIndicator returns the canonical indicator a feed match attests and
// sets what it observed and what enforcement may act on: the name for a
// domain, the address for an IP. Other types (fingerprints, hashes) name
// nothing to block.
func feedIndicator(a *detection.Alert, ev SensorEvent) (value, typ string) {
	value, typ = ev.Indicator, ev.IndicatorType
	switch typ {
	case events.IndicatorDomain:
		if d, ok := events.CanonicalDomain(value); ok {
			value = d
			a.Domain = d
			a.Target = &events.Target{Type: events.TargetDomain, Value: d}
		}
	case events.IndicatorIP:
		if ip, ok := events.CanonicalIP(value); ok {
			value = ip
			a.Target = &events.Target{Type: events.TargetIP, Value: ip}
		}
	}
	return value, typ
}

// between renders a Suricata flow: the household's side first. The packet
// that fired may have gone either way, so no arrow.
func between(ev SensorEvent) string {
	return hostPort(ev.SrcIP, ev.SrcPort) + " ↔ " + hostPort(ev.DstIP, ev.DstPort)
}

func hostPort(ip string, port int) string {
	if port > 0 {
		return net.JoinHostPort(ip, strconv.Itoa(port))
	}
	return ip
}

// flow renders the observation's endpoints for a summary.
func flow(ev SensorEvent) string {
	src, dst := ev.SrcIP, ev.DstIP
	if ev.SrcPort > 0 {
		src = net.JoinHostPort(src, strconv.Itoa(ev.SrcPort))
	}
	if ev.DstPort > 0 {
		dst = net.JoinHostPort(dst, strconv.Itoa(ev.DstPort))
	}
	if dst == "" {
		return src
	}
	return src + " → " + dst
}

// canonicalOrRaw returns the canonical form of an address, or the input
// unchanged when it does not parse, so a bad sensor row fails validation
// visibly instead of carrying a guessed address.
func canonicalOrRaw(ip string) string {
	if c, ok := events.CanonicalIP(ip); ok {
		return c
	}
	return ip
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// signalClass maps a SensorEvent kind to the composite-confidence signal
// vocabulary (step 116).
func signalClass(kind string) string {
	switch kind {
	case "ids-alert":
		return detection.SignalIDS
	case "intel-hit", "ids-dataset":
		return detection.SignalIoC
	case "tls-client":
		return detection.SignalTLS
	case "ml-beacon":
		return detection.SignalBeacon
	case "ml-anomaly":
		return detection.SignalVolumetric
	default:
		return kind
	}
}

func lookup(m *iocmatch.Matcher, iocType, value string) (iocmatch.IoC, bool) {
	switch iocType {
	case "domain":
		return m.MatchDomain(value)
	case "ip":
		return m.MatchIP(value)
	case "ja3", "tlsfp", "md5", "sha256":
		return m.MatchHash(value)
	default:
		return iocmatch.IoC{}, false
	}
}
