package main

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

var testEventSeq atomic.Int64

// testEvent returns a contract-valid single-signal domain IoC detection with
// a fresh id. Tests adjust what they exercise.
func testEvent(confidence int, severity string) events.DetectionEvent {
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            "DET-test-" + strconv.FormatInt(testEventSeq.Add(1), 10),
		Timestamp:     time.Now().UTC(),
		Summary:       "DNS query for a.evil.example matches test domain indicator evil.example",
		Domain:        "a.evil.example",
		MatchedIoC:    "evil.example",
		IoCType:       events.IndicatorDomain,
		ClientIP:      "192.168.1.100",
		Severity:      severity,
		Confidence:    confidence,
		Source:        "test",
		SignalClass:   events.SignalIoC,
		Signals: []events.Signal{{Class: events.SignalIoC, Confidence: confidence,
			Indicator: "evil.example", IndicatorType: events.IndicatorDomain, Source: "test"}},
		Target: &events.Target{Type: events.TargetDomain, Value: "evil.example"},
	}
}

// withDomainTarget points the event's indicator and target at domain.
func withDomainTarget(ev events.DetectionEvent, domain string) events.DetectionEvent {
	ev.MatchedIoC = domain
	ev.Signals = append([]events.Signal(nil), ev.Signals...)
	ev.Signals[0].Indicator = domain
	ev.Target = &events.Target{Type: events.TargetDomain, Value: domain}
	return ev
}
