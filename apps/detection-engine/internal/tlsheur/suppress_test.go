package tlsheur

import (
	"fmt"
	"io"
	"log"
	"log/slog"
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
//
// The cost is counted, not timed: a wall-clock bound on 65 536 inserts
// failed on a loaded runner with -race and coverage, and a fast machine
// would hide a quadratic walk behind it.
func TestSuppressMapIsBounded(t *testing.T) {
	quietLogs(t) // one INFO line per finding, 65 536 of them
	now := time.Unix(1_800_000_000, 0)
	alerts := 0
	a := New(iocmatch.New(), constResolver("cdn.attacker.example"), DefaultLocalCIDRs,
		func(detection.Alert) { alerts++ })
	a.now = func() time.Time { return now }
	evicted := counter(t)
	key := func(i int) string {
		return fmt.Sprintf("192.168.1.66|203.0.113.9|sni-dns-mismatch|r%d.random-sni.example vs cdn.attacker.example", i)
	}
	insert := func(from, to int) {
		for i := from; i < to; i++ {
			a.Handle(ingest.SensorEvent{Kind: "tls-client", Timestamp: now, SrcIP: "192.168.1.66",
				DstIP: "203.0.113.9", SNI: fmt.Sprintf("r%d.random-sni.example", i)})
		}
	}

	// Up to the cap nothing is evicted, and the upkeep looks at nothing.
	insert(0, maxSuppressed)
	if a.examined != 0 || len(a.suppressed) != maxSuppressed {
		t.Fatalf("filling the table: %d entries examined, %d kept", a.examined, len(a.suppressed))
	}
	// Past it, every insert costs the same however full the table is: one
	// eviction, the oldest. The quadratic table walked all 16 384 entries
	// on each of these inserts.
	const n = 4 * maxSuppressed
	insert(maxSuppressed, n)
	if want := n - maxSuppressed; a.examined != want {
		t.Errorf("the table's upkeep examined %d entries for %d inserts past the cap, want %d (one each)",
			a.examined, n-maxSuppressed, want)
	}
	if len(a.suppressed) > maxSuppressed || a.order.Len() != len(a.suppressed) {
		t.Fatalf("suppression table holds %d keys (list %d), cap %d", len(a.suppressed), a.order.Len(), maxSuppressed)
	}
	if alerts != n {
		t.Errorf("alerts = %d, want %d: eviction must never silence a finding", alerts, n)
	}
	if got := counter(t) - evicted; got != n-maxSuppressed {
		t.Errorf("evictions counted %v, want %d", got, n-maxSuppressed)
	}
	// The newest keys are the ones kept, the oldest the ones gone.
	for i, kept := range map[int]bool{n - 1: true, n - maxSuppressed: true, n - maxSuppressed - 1: false, 0: false} {
		if _, ok := a.suppressed[key(i)]; ok != kept {
			t.Errorf("suppression %d kept=%v, want %v: the oldest must go first", i, ok, kept)
		}
	}
}

// quietLogs discards log output until the test ends — a test that makes
// tens of thousands of findings would otherwise print a line for each —
// and then restores the default logger and the log package's output it
// writes through.
func quietLogs(t *testing.T) {
	t.Helper()
	prev, out, flags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(out)
		log.SetFlags(flags)
	})
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
