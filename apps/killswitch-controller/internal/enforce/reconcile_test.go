package enforce

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/libs/events"
)

type stubAdGuard struct {
	mu       sync.Mutex
	rules    []string
	failGets int
	srv      *httptest.Server
}

func newStubAdGuard(t *testing.T, rules ...string) *stubAdGuard {
	a := &stubAdGuard{rules: rules}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, _ *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.failGets > 0 {
			a.failGets--
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"user_rules": a.rules})
	})
	mux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Rules []string }
		json.NewDecoder(r.Body).Decode(&body)
		a.mu.Lock()
		a.rules = body.Rules
		a.mu.Unlock()
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func (a *stubAdGuard) set(rules ...string) {
	a.mu.Lock()
	a.rules = rules
	a.mu.Unlock()
}

func (a *stubAdGuard) get() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.rules...)
}

func sinkEnv(t *testing.T, ag *stubAdGuard) *env {
	t.Helper()
	en := &env{t: t, clk: &clock{real: true}, path: filepath.Join(t.TempDir(), "ks.db")}
	s, err := actions.Open(en.path, actions.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	en.s = s
	en.e = New(s, map[string]drivers.Driver{
		events.ActionDNSSinkhole: drivers.NewSinkholeDriver(ag.srv.URL, "u", "p", s),
	}, Config{ReapInterval: 20 * time.Millisecond, ReconcileInterval: 20 * time.Millisecond})
	return en
}

// TestReconcileRepairsInTheSafeDirection: after a restart the service
// checks what it believes it enforces against AdGuard.
func TestReconcileRepairsInTheSafeDirection(t *testing.T) {
	ag := newStubAdGuard(t, "||operator.example^")
	en := sinkEnv(t, ag)
	keep := en.active("keep.example")
	gone := en.active("gone.example")
	failing := en.active("failing.example")
	en.s.RevertFailed(failing.ID, "alice", "adguard 502", time.Now().Add(time.Hour), true)

	// AdGuard lost gone.example and the failed revert took effect after
	// all; an orphan we once added is still there.
	en.s.ClaimSinkholeRule("ACT-old", "||orphan.example^", true)
	en.s.ReleaseSinkholeRef("ACT-old", false)
	ag.set("||operator.example^", "||keep.example^", "||orphan.example^")

	ag.mu.Lock()
	ag.failGets = 1
	ag.mu.Unlock()
	if err := en.e.Reconcile(context.Background()); err == nil {
		t.Fatal("reconciliation must report an unreadable AdGuard")
	}
	if got := en.get(gone.ID); got.State != events.StateActive {
		t.Fatal("a failed reconciliation changed state")
	}

	if err := en.e.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := en.get(keep.ID); got.State != events.StateActive {
		t.Errorf("an enforced rule that is present: %s", got.State)
	}
	if got := en.get(gone.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorReconcile {
		t.Errorf("a missing rule must be recorded as lifted: %s by %s", got.State, got.RevertedBy)
	}
	if got := en.get(failing.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorReconcile {
		t.Errorf("revert_failed whose rule is gone: %s", got.State)
	}
	rules := ag.get()
	slices.Sort(rules)
	if !slices.Equal(rules, []string{"||keep.example^", "||operator.example^"}) {
		t.Errorf("AdGuard after reconciliation: %v (nothing re-created, orphan gone, operator rule kept)", rules)
	}
}

func TestRunLoopReconcilesAndReaps(t *testing.T) {
	ag := newStubAdGuard(t)
	en := sinkEnv(t, ag)
	r := en.pending("x.example")
	en.s.Approve(r.ID, "alice", "", time.Now())
	en.s.Activate(r.ID, "alice", "")
	ag.set() // the rule never made it (or was lost)
	en.s.ClaimSinkholeRule(r.ID, "||x.example^", true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { en.e.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for en.get(r.ID).State != events.StateReverted && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got := en.get(r.ID); got.State != events.StateReverted {
		t.Fatalf("the loop did not reconcile: %s", got.State)
	}
	en.e.Shutdown(time.Second)
}
