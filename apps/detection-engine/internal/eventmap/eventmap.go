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
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
)

// validIoCTypes are the ioc_type values the DetectionEvent schema allows.
var validIoCTypes = map[string]struct{}{
	"domain": {}, "ip": {}, "url": {}, "ja3": {}, "tlsfp": {}, "md5": {}, "sha256": {},
}

// AlertToEvent maps an internal Alert to the shared contract, coercing the
// ioc_type to a schema-valid value (beacon/flow-window signals carry
// descriptive types that aren't in the enum → normalized to "ip").
func AlertToEvent(a detection.Alert) events.DetectionEvent {
	iocType := a.IoCType
	if _, ok := validIoCTypes[iocType]; !ok {
		iocType = "ip"
	}
	sev := a.Severity
	if sev == "" {
		sev = detection.SeverityForConfidence(a.Confidence)
	}
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            a.ID,
		Timestamp:     a.Timestamp,
		Domain:        a.Domain,
		MatchedIoC:    a.MatchedIoC,
		IoCType:       iocType,
		ClientIP:      a.ClientIP,
		ClientMAC:     a.ClientMAC,
		Severity:      sev,
		Confidence:    a.Confidence,
		Source:        a.Source,
		Threat:        a.Threat,
		MitreID:       a.MitreID,
		MitreName:     a.MitreName,
		QueryType:     a.QueryType,
		Tags:          a.Tags,
		Signals:       a.Signals,
		SignalCount:   a.SignalCount,
	}
}
