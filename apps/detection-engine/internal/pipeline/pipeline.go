// Package pipeline is the one path every detection takes once it is made:
// recorded in the alert history, checked against analyst suppressions,
// correlated into composites, and handed to the outbox for delivery.
package pipeline

import (
	"log/slog"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/eventmap"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// invalidEvents counts detections dropped because they would not validate.
// Non-zero means a producer is building events the killswitch refuses.
var invalidEvents = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Name:      "invalid_events_total",
	Help:      "Detections not forwarded because they break the event contract.",
})

// replayed counts detections dropped because their input record had already
// made one: the record was read a second time.
var replayed = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Name:      "replayed_detections_total",
	Help:      "Detections dropped because their input record (querylog entry, sensor row) had already made one.",
})

func init() {
	prometheus.MustRegister(invalidEvents, replayed)
}

// AlertStore records alerts (*store.Alerts).
type AlertStore interface {
	Add(detection.Alert) error
}

// Suppressor answers analyst false-positive verdicts (*feedback.Store).
type Suppressor interface {
	Suppressed(detection.Alert) bool
	CountSuppressed()
}

// Correlator combines signals per client (*composite.Correlator, built with
// a nil emit callback: the pipeline acts on what Observe returns).
type Correlator interface {
	Observe(detection.Alert) *detection.Alert
}

// Pipeline handles detections. Any field but Alerts may be nil. Safe for
// concurrent use when its parts are.
type Pipeline struct {
	Alerts    AlertStore
	Suppress  Suppressor
	Correlate Correlator
	// Forward delivers a detection; nil when no receiver is configured.
	Forward func(detection.Alert)
	// Records is the ledger of input records already handled; nil handles
	// every detection.
	Records RecordLedger
}

// RecordLedger remembers input records that made a detection
// (*store.Records).
type RecordLedger interface {
	Seen(record string) bool
	Remember(record string)
}

// Handle takes one single-signal detection.
//
// A detection from an input record that already made one is that record
// read again — the readers look a little behind where they stopped, and a
// restart re-reads from the last stored position — and is dropped before it
// can be recorded, correlated or delivered a second time. The record is
// remembered only once the detection is queued, so a crash in between makes
// it again rather than lose it.
//
// Every other detection is recorded, suppressed or not: suppression decides
// what reaches the killswitch, not what the analyst can see — and what was
// recorded under a verdict says so (Suppressed), so it does not read as a new
// alert. A composite formed by this detection supersedes it for delivery —
// unless the composite itself is suppressed. A verdict on a combination says
// the combination is benign, not that this detection is: it is then judged,
// and delivered, on its own.
func (p *Pipeline) Handle(a detection.Alert) {
	if a.Record != "" && p.Records != nil {
		if p.Records.Seen(a.Record) {
			replayed.Inc()
			return
		}
		defer p.Records.Remember(a.Record)
	}
	a.Suppressed = p.suppressed(a)
	p.record(a)
	if a.Suppressed {
		return
	}
	if p.Correlate != nil {
		if comp := p.Correlate.Observe(a); comp != nil {
			comp.Suppressed = p.suppressed(*comp)
			p.record(*comp)
			if !comp.Suppressed {
				p.forward(*comp)
				return
			}
		}
	}
	p.forward(a)
}

func (p *Pipeline) record(a detection.Alert) {
	if p.Alerts == nil {
		return
	}
	if err := p.Alerts.Add(a); err != nil {
		slog.Warn("alert not recorded in the local store", "id", a.ID, "error", err)
	}
}

func (p *Pipeline) suppressed(a detection.Alert) bool {
	if p.Suppress == nil || !p.Suppress.Suppressed(a) {
		return false
	}
	p.Suppress.CountSuppressed()
	return true
}

func (p *Pipeline) forward(a detection.Alert) {
	if p.Forward != nil {
		p.Forward(a)
	}
}

// Outbox queues events durably (*store.Outbox).
type Outbox interface {
	Enqueue(events.DetectionEvent) (string, error)
}

// Forwarder turns an alert into a contract event and queues it.
type Forwarder struct {
	Outbox Outbox
	// Notify wakes the dispatcher after an event was queued.
	Notify func()
}

// Forward validates and queues one detection.
func (f *Forwarder) Forward(a detection.Alert) {
	ev := eventmap.AlertToEvent(a)
	// The receiver would refuse it anyway; refusing here keeps the reason
	// in this service's log and metrics, next to the producer that built
	// it, instead of a 4xx line on the other side.
	if err := ev.Validate(); err != nil {
		invalidEvents.Inc()
		slog.Error("detection not forwarded: it breaks the event contract",
			"id", a.ID, "signal_class", a.SignalClass, "error", err)
		return
	}
	res, err := f.Outbox.Enqueue(ev)
	if err != nil {
		slog.Error("detection could not be queued for delivery", "id", ev.ID,
			"severity", ev.Severity, "error", err)
		return
	}
	if res == store.Queued && f.Notify != nil {
		f.Notify()
	}
}
