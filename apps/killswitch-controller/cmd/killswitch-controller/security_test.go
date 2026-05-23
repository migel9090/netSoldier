package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

type recordingDriver struct {
	applied  atomic.Int32
	reverted atomic.Int32
}

func (d *recordingDriver) Apply(_ context.Context, _ *events.EnforcementAction) error {
	d.applied.Add(1)
	return nil
}

func (d *recordingDriver) Revert(_ context.Context, _ *events.EnforcementAction) error {
	d.reverted.Add(1)
	return nil
}

func (d *recordingDriver) Name() string { return "recording" }

var _ drivers.Driver = (*recordingDriver)(nil)

func newAuthTestEnv(t *testing.T, apiKey string) (*httptest.Server, *actions.Store) {
	t.Helper()
	pol := policy.DefaultPolicy()
	store := actions.NewStore(actions.NopAuditWriter{})
	resolve := func(string) drivers.Driver { return nopDriver{} }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /policy", handleGetPolicy(pol))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))
	mux.HandleFunc("GET /actions/pending", handleListByState(store, events.StatePending))
	mux.HandleFunc("GET /actions/active", handleListByState(store, events.StateActive))
	mux.HandleFunc("GET /actions/{id}", handleGetAction(store))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))
	mux.HandleFunc("POST /actions/{id}/approve", handleApprove(store, resolve))
	mux.HandleFunc("POST /actions/{id}/reject", handleReject(store))
	mux.HandleFunc("POST /actions/{id}/revert", handleRevert(store, resolve))

	srv := httptest.NewServer(authMiddleware(apiKey, mux))
	t.Cleanup(srv.Close)
	return srv, store
}

// --- Allowlist: devices on the allowlist must NEVER be blocked ---

func TestSecAllowlistBlocksAllSeverities(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	pol.AutoMinConfidence = 0
	pol.AutoMinSeverity = events.SeverityLow

	for _, sev := range []string{
		events.SeverityLow,
		events.SeverityMedium,
		events.SeverityHigh,
		events.SeverityCritical,
	} {
		t.Run(sev, func(t *testing.T) {
			d := pol.Evaluate(events.DetectionEvent{
				Confidence: 100,
				Severity:   sev,
				ClientMAC:  "aa:bb:cc:dd:ee:ff",
				ClientIP:   "192.168.1.42",
			})
			if d.Action != "ignore" {
				t.Errorf("severity %s: got %q, want ignore", sev, d.Action)
			}
		})
	}
}

func TestSecAllowlistProtectsViaIPAlone(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddIP("192.168.1.1")

	d := pol.Evaluate(events.DetectionEvent{
		Confidence: 100,
		Severity:   events.SeverityCritical,
		ClientMAC:  "ff:ff:ff:ff:ff:ff",
		ClientIP:   "192.168.1.1",
	})
	if d.Action != "ignore" {
		t.Errorf("IP-only allowlisted: got %q, want ignore", d.Action)
	}
}

func TestSecAllowlistProtectsViaMACAlone(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	d := pol.Evaluate(events.DetectionEvent{
		Confidence: 100,
		Severity:   events.SeverityCritical,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "10.99.99.99",
	})
	if d.Action != "ignore" {
		t.Errorf("MAC-only allowlisted: got %q, want ignore", d.Action)
	}
}

func TestSecAllowlistNoDriverApplied(t *testing.T) {
	drv := &recordingDriver{}
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	store := actions.NewStore(actions.NopAuditWriter{})
	resolve := func(string) drivers.Driver { return drv }

	mux := http.NewServeMux()
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(events.DetectionEvent{
		ID:         "DET-SEC-1",
		Severity:   events.SeverityCritical,
		Confidence: 100,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "192.168.1.42",
		Domain:     "evil.com",
	})
	resp, err := http.Post(srv.URL+"/evaluate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if d := result["decision"].(map[string]any); d["Action"] != "ignore" {
		t.Errorf("decision: got %v, want ignore", d["Action"])
	}
	if result["action"] != nil {
		t.Error("no enforcement action should be created for allowlisted device")
	}
	if drv.applied.Load() != 0 {
		t.Errorf("driver.Apply called %d times, want 0", drv.applied.Load())
	}
	if n := len(store.ListByState(events.StatePending)) + len(store.ListByState(events.StateActive)); n != 0 {
		t.Errorf("store has %d pending/active actions, want 0", n)
	}
}

func TestSecAllowlistConcurrentEvaluations(t *testing.T) {
	drv := &recordingDriver{}
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	store := actions.NewStore(actions.NopAuditWriter{})
	resolve := func(string) drivers.Driver { return drv }

	mux := http.NewServeMux()
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(events.DetectionEvent{
				Severity:   events.SeverityCritical,
				Confidence: 100,
				ClientMAC:  "aa:bb:cc:dd:ee:ff",
				ClientIP:   "192.168.1.42",
			})
			resp, err := http.Post(srv.URL+"/evaluate", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Errorf("POST /evaluate: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()

	if drv.applied.Load() != 0 {
		t.Errorf("driver.Apply called %d times during concurrent eval, want 0", drv.applied.Load())
	}
	if cnt := len(store.ListByState(events.StatePending)) + len(store.ListByState(events.StateActive)); cnt != 0 {
		t.Errorf("store has %d actions after concurrent allowlist eval, want 0", cnt)
	}
}

// --- Authorization: POST endpoints require valid Bearer token ---

func TestSecAuthRequiredAllPOSTEndpoints(t *testing.T) {
	srv, store := newAuthTestEnv(t, "secret-key")

	a := store.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 3600, false, "evil.com")

	endpoints := []struct {
		path string
		body any
	}{
		{"/evaluate", events.DetectionEvent{Severity: events.SeverityCritical, Confidence: 99, ClientIP: "10.0.0.1"}},
		{"/actions/" + a.ID + "/approve", map[string]string{"approved_by": "admin"}},
		{"/actions/" + a.ID + "/reject", map[string]string{"reason": "test"}},
		{"/actions/" + a.ID + "/revert", map[string]string{"reason": "test"}},
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			data, _ := json.Marshal(ep.body)
			resp, err := http.Post(srv.URL+ep.path, "application/json", bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("POST %s without auth: got %d, want 401", ep.path, resp.StatusCode)
			}
		})
	}
}

func TestSecAuthRejectsInvalidSchemes(t *testing.T) {
	srv, _ := newAuthTestEnv(t, "secret-key")

	cases := []struct {
		name  string
		value string
	}{
		{"raw_key", "secret-key"},
		{"basic_scheme", "Basic secret-key"},
		{"bearer_wrong_key", "Bearer wrong-key"},
		{"bearer_empty_token", "Bearer "},
		{"bearer_no_space", "Bearer"},
		{"lowercase_bearer", "bearer secret-key"},
	}

	body, _ := json.Marshal(events.DetectionEvent{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", srv.URL+"/evaluate", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", tc.value)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("auth %q: got %d, want 401", tc.value, resp.StatusCode)
			}
		})
	}
}

func TestSecAuthGETPassthrough(t *testing.T) {
	srv, _ := newAuthTestEnv(t, "secret-key")

	paths := []string{"/healthz", "/policy", "/allowlist", "/actions/pending", "/actions/active"}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("GET %s without auth: got %d, want 200", path, resp.StatusCode)
			}
		})
	}
}

// --- Auto-revert: TTL-expired actions are reverted automatically ---

func TestSecTTLExpiryDetected(t *testing.T) {
	store := actions.NewStore(actions.NopAuditWriter{})

	a := store.Create("DET-TTL-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 1, true, "evil.com")
	if err := store.Activate(a.ID); err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)

	expired := store.ListExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired action, got %d", len(expired))
	}
	if expired[0].ID != a.ID {
		t.Errorf("expired action ID: got %q, want %q", expired[0].ID, a.ID)
	}
}

func TestSecTTLOnlyActiveActionsExpire(t *testing.T) {
	store := actions.NewStore(actions.NopAuditWriter{})

	store.Create("DET-TTL-2", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 1, false, "evil.com")

	store.Create("DET-TTL-3", "bb:cc:dd:ee:ff:00", "192.168.1.11",
		events.ActionDNSSinkhole, "test", 1, true, "evil2.com")

	time.Sleep(1100 * time.Millisecond)

	if expired := store.ListExpired(); len(expired) != 0 {
		t.Errorf("non-active actions should not expire, got %d", len(expired))
	}
}

func TestSecTTLNoExpiryWithoutTTL(t *testing.T) {
	store := actions.NewStore(actions.NopAuditWriter{})

	a := store.Create("DET-TTL-4", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 0, true, "evil.com")
	if err := store.Activate(a.ID); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if expired := store.ListExpired(); len(expired) != 0 {
		t.Errorf("action without TTL should never expire, got %d", len(expired))
	}
}

func TestSecAutoRevertLifecycle(t *testing.T) {
	drv := &recordingDriver{}
	store := actions.NewStore(actions.NopAuditWriter{})

	a := store.Create("DET-TTL-5", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "auto: critical+100", 1, true, "evil.com")
	drv.Apply(context.Background(), a)
	store.Activate(a.ID)

	if got := store.Get(a.ID); got.State != events.StateActive {
		t.Fatalf("expected active, got %q", got.State)
	}

	time.Sleep(1100 * time.Millisecond)

	expired := store.ListExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}

	drv.Revert(context.Background(), &expired[0])
	store.Revert(expired[0].ID, "TTL expired")

	got := store.Get(a.ID)
	if got.State != events.StateReverted {
		t.Errorf("expected reverted after TTL, got %q", got.State)
	}
	if got.RevertedAt == nil {
		t.Error("RevertedAt should be set after auto-revert")
	}
	if drv.reverted.Load() != 1 {
		t.Errorf("driver.Revert called %d times, want 1", drv.reverted.Load())
	}
	if len(store.ListExpired()) != 0 {
		t.Error("reverted action should not appear in ListExpired")
	}
}

func TestSecAutoRevertDoesNotAffectOtherActions(t *testing.T) {
	store := actions.NewStore(actions.NopAuditWriter{})

	short := store.Create("DET-TTL-6", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 1, true, "evil.com")
	store.Activate(short.ID)

	long := store.Create("DET-TTL-7", "bb:cc:dd:ee:ff:00", "192.168.1.11",
		events.ActionDNSSinkhole, "test", 3600, true, "bad.com")
	store.Activate(long.ID)

	time.Sleep(1100 * time.Millisecond)

	expired := store.ListExpired()
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}
	if expired[0].ID != short.ID {
		t.Errorf("wrong expired action: got %q, want %q", expired[0].ID, short.ID)
	}

	if got := store.Get(long.ID); got.State != events.StateActive {
		t.Errorf("long-TTL action should still be active, got %q", got.State)
	}
}
