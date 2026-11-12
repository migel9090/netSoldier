// Package eventmap converts the detection-engine's internal Alert into the
// shared, versioned events.DetectionEvent contract (libs/events).
//
// Before step 116 the engine posted a bespoke {event, alert, service}
// envelope to the killswitch's /evaluate, which decodes a flat
// DetectionEvent — so the fields never lined up and every evaluation saw
// confidence 0. This is the single funnel that makes the wire contract
// between detection-engine and killswitch-controller real.
package eventmap

import (
	"fmt"
	"strings"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
)

// AlertToEvent maps an internal Alert to the shared contract.
//
// Producers are expected to fill Summary, Signals and Target themselves;
// they know what they observed. The fallbacks here only keep an alert from
// an incomplete producer valid in the most conservative way: a generic
// summary, one signal carrying the alert's class and confidence but NO
// indicator, and no target. Such an event can be shown and queued for a
// human, never enforced automatically — inventing an indicator here would be
// exactly the guess the typed target exists to stop.
//
// Validate the result before sending it; an alert that cannot be made valid
// (no class, unparsable client address) must be reported, not delivered.
func AlertToEvent(a detection.Alert) events.DetectionEvent {
	sev := a.Severity
	if sev == "" {
		sev = detection.SeverityForConfidence(a.Confidence)
	}
	clientIP := a.ClientIP
	if c, ok := events.CanonicalIP(clientIP); ok {
		clientIP = c
	}

	signals := a.Signals
	if len(signals) == 0 && a.SignalClass != "" && a.SignalClass != detection.SignalComposite {
		signals = []events.Signal{{
			Class:      a.SignalClass,
			Confidence: detection.ClampConfidence(a.Confidence),
			Source:     a.Source,
		}}
	}
	ev := events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            a.ID,
		Timestamp:     a.Timestamp,
		Summary:       a.Summary,
		Domain:        a.Domain,
		MatchedIoC:    a.MatchedIoC,
		IoCType:       a.IoCType,
		ClientIP:      clientIP,
		ClientMAC:     strings.ToLower(a.ClientMAC),
		ClientName:    a.ClientName,
		Severity:      sev,
		Confidence:    a.Confidence,
		Source:        a.Source,
		Threat:        a.Threat,
		MitreID:       a.MitreID,
		MitreName:     a.MitreName,
		QueryType:     a.QueryType,
		Tags:          a.Tags,
		SignalClass:   a.SignalClass,
		Signals:       signals,
		Target:        a.Target,
	}
	if ev.SignalClass == "" {
		ev.SignalClass = classOf(signals)
	}
	if strings.TrimSpace(ev.Summary) == "" {
		ev.Summary = fallbackSummary(ev)
	}
	return ev
}

// classOf derives signal_class from the signals the way the contract defines
// it: the single class, or composite for more than one.
func classOf(signals []events.Signal) string {
	ev := events.DetectionEvent{Signals: signals}
	switch classes := ev.ContributingClasses(); len(classes) {
	case 0:
		return ""
	case 1:
		return classes[0]
	default:
		return detection.SignalComposite
	}
}

func fallbackSummary(ev events.DetectionEvent) string {
	what := ev.SignalClass
	if what == "" {
		what = "unclassified"
	}
	s := fmt.Sprintf("%s detection for %s", what, ev.ClientIP)
	if ev.Threat != "" {
		s += ": " + ev.Threat
	}
	return s
}
