package isolate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// fakeTx records what the engine asked to be put on the wire.
type fakeTx struct {
	mu       sync.Mutex
	applies  int
	lifts    int
	failNext bool
}

func (f *fakeTx) Apply(_, _ wire.Host) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext {
		f.failNext = false
		return errFail
	}
	f.applies++
	return nil
}
func (f *fakeTx) Lift(_, _ wire.Host) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lifts++
	return nil
}
func (f *fakeTx) counts() (int, int) { f.mu.Lock(); defer f.mu.Unlock(); return f.applies, f.lifts }

type errString string

func (e errString) Error() string { return string(e) }

const errFail = errString("send failed")

// collect gathers reported results.
type collector struct {
	mu sync.Mutex
	rs []proto.Result
}

func (c *collector) add(r proto.Result) { c.mu.Lock(); c.rs = append(c.rs, r); c.mu.Unlock() }
func (c *collector) last() proto.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.rs) == 0 {
		return proto.Result{}
	}
	return c.rs[len(c.rs)-1]
}

func newEngine(t *testing.T, tx Transmitter) (*Engine, *collector) {
	t.Helper()
	c := &collector{}
	// Short timings so expiry and refresh are observable in a test.
	refreshEvery, liftRounds, liftGap = 10*time.Millisecond, 1, 0
	e := NewEngine(newGuard(), tx, 2, 100, c.add)
	return e, c
}

func isoCmd(id, mac, ip string, ttl int64) proto.Command {
	return proto.Command{ID: id, Type: proto.CmdARPIsolate, MAC: mac, IP: ip, TTLSeconds: ttl}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func TestIsolateThenRelease(t *testing.T) {
	tx := &fakeTx{}
	e, c := newEngine(t, tx)
	defer e.Shutdown()

	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	if !c.last().OK {
		t.Fatalf("isolate not OK: %+v", c.last())
	}
	if a := e.Active(); len(a) != 1 || a[0].IP != "192.168.1.77" {
		t.Fatalf("active = %+v", a)
	}
	applies, _ := tx.counts()
	if applies < 1 {
		t.Fatal("no apply sent")
	}

	e.Handle(context.Background(), proto.Command{ID: "i-2", Type: proto.CmdARPRelease, MAC: "aa:bb:cc:dd:ee:77"})
	waitFor(t, func() bool { _, lifts := tx.counts(); return lifts > 0 })
	if len(e.Active()) != 0 {
		t.Fatal("still active after release")
	}
}

// TestTTLIsEnforcedLocally: with no release at all, the isolation ends and
// the target is restored when its TTL passes — the killswitch may have died.
func TestTTLIsEnforcedLocally(t *testing.T) {
	tx := &fakeTx{}
	e, _ := newEngine(t, tx)
	defer e.Shutdown()

	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 1))
	waitFor(t, func() bool { _, lifts := tx.counts(); return lifts > 0 && len(e.Active()) == 0 })
}

// TestShutdownRestoresEverything: a clean stop lifts every isolation.
func TestShutdownRestoresEverything(t *testing.T) {
	tx := &fakeTx{}
	e, _ := newEngine(t, tx)
	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	e.Handle(context.Background(), isoCmd("i-2", "aa:bb:cc:dd:ee:78", "192.168.1.78", 3600))
	if len(e.Active()) != 2 {
		t.Fatalf("active = %d", len(e.Active()))
	}
	e.Shutdown()
	if _, lifts := tx.counts(); lifts < 2 {
		t.Fatalf("shutdown lifted %d of 2", lifts)
	}
	if len(e.Active()) != 0 {
		t.Fatal("active after shutdown")
	}
}

func TestConcurrentIsolationCap(t *testing.T) {
	tx := &fakeTx{}
	e, c := newEngine(t, tx) // cap is 2
	defer e.Shutdown()
	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	e.Handle(context.Background(), isoCmd("i-2", "aa:bb:cc:dd:ee:78", "192.168.1.78", 3600))
	e.Handle(context.Background(), isoCmd("i-3", "aa:bb:cc:dd:ee:79", "192.168.1.79", 3600))
	if c.last().OK {
		t.Fatal("third isolation accepted past the cap")
	}
	if e.Refusals()["capacity"] != 1 {
		t.Fatalf("capacity refusals = %v", e.Refusals())
	}
}

func TestApplyFailureIsReportedNotRecorded(t *testing.T) {
	tx := &fakeTx{failNext: true}
	e, c := newEngine(t, tx)
	defer e.Shutdown()
	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	if c.last().OK {
		t.Fatal("isolation reported OK despite a send failure")
	}
	if len(e.Active()) != 0 {
		t.Fatal("a failed isolation must not be recorded as active")
	}
}

func TestRefusalIsReportedInResults(t *testing.T) {
	tx := &fakeTx{}
	e, c := newEngine(t, tx)
	defer e.Shutdown()
	e.Handle(context.Background(), isoCmd("i-1", "ff:ff:ff:ff:ff:ff", "192.168.1.77", 3600))
	r := c.last()
	if r.OK || r.ID != "i-1" || r.Error == "" {
		t.Fatalf("expected a reported refusal, got %+v", r)
	}
	if e.Refusals()["group_mac"] != 1 {
		t.Fatalf("group_mac not counted: %v", e.Refusals())
	}
}

func TestReleaseOfUnknownIsSuccess(t *testing.T) {
	tx := &fakeTx{}
	e, c := newEngine(t, tx)
	defer e.Shutdown()
	e.Handle(context.Background(), proto.Command{ID: "i-9", Type: proto.CmdARPRelease, MAC: "aa:bb:cc:dd:ee:77"})
	if !c.last().OK {
		t.Fatal("releasing something not isolated should be reported OK")
	}
}

func TestRepeatedIsolateExtends(t *testing.T) {
	tx := &fakeTx{}
	e, c := newEngine(t, tx)
	defer e.Shutdown()
	e.Handle(context.Background(), isoCmd("i-1", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	e.Handle(context.Background(), isoCmd("i-1b", "aa:bb:cc:dd:ee:77", "192.168.1.77", 3600))
	if !c.last().OK || len(e.Active()) != 1 {
		t.Fatalf("repeat should extend, active=%d last=%+v", len(e.Active()), c.last())
	}
}
