package pipeline

import (
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/composite"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/feedback"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestReplayedDetectionIsNotRecordedOrDeliveredAgain: the readers re-read
// the overlap behind their cursor, and after a restart the stretch since the
// last stored position. Detections from those rows name the row, and the
// ledger of handled records recognises them: they are neither recorded, nor
// correlated, nor queued a second time — even though a new process gives
// them new ids, so the history's and the outbox's id checks would not
// catch them, and even when the original was enqueued longer ago than the
// outbox's aggregation window, which would let it through again.
func TestReplayedDetectionIsNotRecordedOrDeliveredAgain(t *testing.T) {
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	alerts := st.Alerts(0, 0)
	ob, err := st.Outbox(time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	fw := &Forwarder{Outbox: ob}
	p := &Pipeline{Alerts: alerts, Suppress: feedback.New(nil), Correlate: composite.New(15*time.Minute, nil),
		Forward: fw.Forward, Records: st.Records(time.Hour)}
	withID := func(a detection.Alert) detection.Alert { a.ID = detection.NewID(); return a }

	row := ingest.SensorEvent{Sensor: "zeek", Kind: "intel-hit", Timestamp: time.Now().UTC(),
		SrcIP: "192.168.1.60", DstIP: "192.168.1.2", Indicator: "c2.real-threat.example",
		IndicatorType: "domain", Source: "threatfox", Signature: "DNS::IN_REQUEST",
		Origin: "zeek_intel", RowKey: "1234567890"}
	beaconRow := ingest.SensorEvent{Sensor: "ml-anomaly", Kind: "ml-beacon", Timestamp: time.Now().UTC(),
		SrcIP: "192.168.1.60", DstIP: "198.51.100.20", DstDomain: "telemetry.vendor.example",
		Confidence: 75, Severity: "high", Source: "rita", Origin: "ml_beacons", RowKey: "42"}

	before := testutil.ToFloat64(replayed)
	p.Handle(withID(ingest.ToAlert(row, nil)))
	p.Handle(withID(ingest.ToAlert(beaconRow, nil))) // forms a composite with the feed hit
	recorded, _ := alerts.Recent(100)
	pending := ob.Pending()
	if len(recorded) != 3 || pending != 2 {
		t.Fatalf("first read: %d alerts, %d queued; want feed hit, beacon and composite recorded, "+
			"the feed hit and the composite queued", len(recorded), pending)
	}

	// Delivered long ago and purged from the outbox: aggregation alone would
	// no longer absorb a repeat.
	for {
		e, ok, err := ob.Next(time.Now())
		if err != nil || !ok {
			break
		}
		if err := ob.Delivered(e.Seq); err != nil {
			t.Fatal(err)
		}
	}

	// The same rows, read again by a process that gives them new ids.
	p.Handle(withID(ingest.ToAlert(row, nil)))
	p.Handle(withID(ingest.ToAlert(beaconRow, nil)))
	if got, _ := alerts.Recent(100); len(got) != 3 {
		t.Errorf("re-read rows recorded again: %d alerts", len(got))
	}
	if ob.Pending() != 0 {
		t.Errorf("re-read rows queued again: %d pending", ob.Pending())
	}
	if n := testutil.ToFloat64(replayed) - before; n != 2 {
		t.Errorf("replayed counter +%v, want +2", n)
	}

	// A detection without a record is not affected, nor is a new row.
	p.Handle(withID(ingest.ToAlert(ingest.SensorEvent{Kind: "intel-hit", SrcIP: "192.168.1.61",
		Indicator: "c2.real-threat.example", IndicatorType: "domain"}, nil)))
	row.RowKey, row.SrcIP = "1234567891", "192.168.1.62"
	p.Handle(withID(ingest.ToAlert(row, nil)))
	if got, _ := alerts.Recent(100); len(got) != 5 {
		t.Errorf("new detections were dropped: %d alerts, want 5", len(got))
	}
}
