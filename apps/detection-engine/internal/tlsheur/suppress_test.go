package tlsheur

import (
	"fmt"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	dto "github.com/prometheus/client_model/go"
)

type constResolver string

func (r constResolver) Get(_, _ string) string { return string(r) }

// TestSuppressMapIsBounded: SNI is chosen by the client, so a handshake with
// a fresh random name is a new suppression key — and a new finding. The map
// inserted even when its sweep freed nothing, and swept all of itself on
// every insert past the limit: it grew without bound and each insert walked
// it whole.
func TestSuppressMapIsBounded(t *testing.T) {
	alerts := 0
	a := New(iocmatch.New(), constResolver("cdn.attacker.example"), DefaultLocalCIDRs,
		func(detection.Alert) { alerts++ })
	evicted := counter(t)
	const n = 4 * maxSuppressed
	start := time.Now()
	for i := 0; i < n; i++ {
		a.Handle(ingest.SensorEvent{Kind: "tls-client", Timestamp: time.Now(), SrcIP: "192.168.1.66",
			DstIP: "203.0.113.9", SNI: fmt.Sprintf("r%d.random-sni.example", i)})
	}
	elapsed := time.Since(start)
	if len(a.suppressed) > maxSuppressed || a.order.Len() != len(a.suppressed) {
		t.Fatalf("suppression table holds %d keys (list %d), cap %d", len(a.suppressed), a.order.Len(), maxSuppressed)
	}
	if alerts != n {
		t.Errorf("alerts = %d, want %d: eviction must never silence a finding", alerts, n)
	}
	if got := counter(t) - evicted; got != n-maxSuppressed {
		t.Errorf("evictions counted %v, want %d", got, n-maxSuppressed)
	}
	// Quadratic behaviour took tens of seconds here; linear is milliseconds.
	if elapsed > 5*time.Second {
		t.Errorf("%d inserts took %s", n, elapsed)
	}
	// The newest keys are the ones kept.
	if _, ok := a.suppressed[fmt.Sprintf("192.168.1.66|203.0.113.9|sni-dns-mismatch|r%d.random-sni.example vs cdn.attacker.example", n-1)]; !ok {
		t.Error("the newest suppression was evicted instead of the oldest")
	}
}

// TestSuppressionExpiresAndIsSweptPeriodically: within the window a finding
// is suppressed; after it, it fires again; expired entries leave the table
// on the periodic sweep, not on every insert.
func TestSuppressionExpiresAndIsSweptPeriodically(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	alerts := 0
	a := New(iocmatch.New(), constResolver("cdn.attacker.example"), DefaultLocalCIDRs,
		func(detection.Alert) { alerts++ })
	a.now = func() time.Time { return now }
	ev := func(sni string) ingest.SensorEvent {
		return ingest.SensorEvent{Kind: "tls-client", SrcIP: "192.168.1.66", DstIP: "203.0.113.9", SNI: sni}
	}

	a.Handle(ev("one.example"))
	a.Handle(ev("one.example"))
	if alerts != 1 {
		t.Fatalf("repeat inside the window fired: %d", alerts)
	}
	for i := 0; i < 10; i++ {
		a.Handle(ev(fmt.Sprintf("n%d.example", i)))
	}
	now = now.Add(suppressWindow + time.Second)
	a.Handle(ev("one.example"))
	if alerts != 12 {
		t.Fatalf("after the window the finding must fire again: alerts=%d", alerts)
	}
	if len(a.suppressed) != 1 {
		t.Errorf("the sweep left %d entries, want only the one just re-added", len(a.suppressed))
	}
	// Until the next sweep is due nothing walks the table.
	now = now.Add(suppressWindow + time.Second)
	a.nextSweep = now.Add(time.Minute)
	a.Handle(ev("two.example"))
	if len(a.suppressed) != 2 {
		t.Errorf("entries = %d: an insert between sweeps must not sweep", len(a.suppressed))
	}
}

func counter(t *testing.T) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := suppressEvicted.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}
