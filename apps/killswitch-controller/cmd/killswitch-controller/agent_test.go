package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/enforce"
	"github.com/migel9090/netSoldier/libs/events"
)

// stubAgent plays the netagent side of contract §8.2 over HTTP: it polls,
// carries out (pretends to) every command it is given unless told to
// refuse, and reports what it has in force.
type stubAgent struct {
	t      *testing.T
	h      *harness
	token  string
	refuse map[string]string // command type → error

	mu      sync.Mutex
	active  map[string]drivers.AgentIsolation
	results []drivers.AgentResult
	seen    []drivers.AgentCommand
}

func newStubAgent(h *harness) *stubAgent {
	return &stubAgent{t: h.t, h: h, token: testAgentToken, refuse: map[string]string{},
		active: map[string]drivers.AgentIsolation{}}
}

func (a *stubAgent) poll() int {
	a.t.Helper()
	a.mu.Lock()
	req := drivers.PollRequest{Agent: "stub", Results: a.results, Active: []drivers.AgentIsolation{}}
	for _, iso := range a.active {
		req.Active = append(req.Active, iso)
	}
	a.results = nil
	a.mu.Unlock()
	body, _ := json.Marshal(req)
	status, raw := a.h.request(http.MethodPost, "/agent/v1/poll", a.token, body, nil)
	if status != http.StatusOK {
		return status
	}
	var resp drivers.PollResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		a.t.Fatalf("poll response %q: %v", raw, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range resp.Commands {
		a.seen = append(a.seen, c)
		if msg, ok := a.refuse[c.Type]; ok {
			a.results = append(a.results, drivers.AgentResult{ID: c.ID, OK: false, Error: msg})
			continue
		}
		switch c.Type {
		case drivers.CommandIsolate:
			a.active[c.MAC] = drivers.AgentIsolation{MAC: c.MAC, IP: c.IP,
				Expires: time.Now().Add(time.Duration(c.TTLSeconds) * time.Second).UTC().Format(time.RFC3339)}
		case drivers.CommandRelease:
			delete(a.active, c.MAC)
		}
		a.results = append(a.results, drivers.AgentResult{ID: c.ID, OK: true})
	}
	return status
}

// run polls every few milliseconds until the test ends.
func (a *stubAgent) run() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			a.poll()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	a.t.Cleanup(func() { cancel(); <-done })
}

func agentHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, harnessOpts{
		engine: enforce.Config{ConfirmTimeout: 2 * time.Second},
		driversFor: func(s *actions.Store) map[string]drivers.Driver {
			var guard drivers.TargetGuard
			if err := guard.ProtectIP("192.168.1.1"); err != nil {
				t.Fatal(err)
			}
			return map[string]drivers.Driver{
				events.ActionDNSSinkhole: &recordingDriver{},
				events.ActionARPIsolate:  drivers.NewARPIsolateDriver(s, &guard, nil),
			}
		},
	})
}

// TestARPIsolationThroughTheAgent: the raw-socket driver is gone; an
// isolation is a command the agent fetches, and the action is active only
// once the agent confirmed it.
func TestARPIsolationThroughTheAgent(t *testing.T) {
	h := agentHarness(t)
	agent := newStubAgent(h)
	a := h.createPending("02:00:00:00:00:31", "192.168.1.31", "x.example")

	// No agent yet: isolation is not offered.
	if status, got := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate}); status != http.StatusUnprocessableEntity ||
		!strings.Contains(got.Error, "no netagent") {
		t.Fatalf("without an agent: %d %+v", status, got)
	}
	agent.run()
	time.Sleep(30 * time.Millisecond)
	var pol map[string]any
	h.get("/policy", &pol)
	if !strings.Contains(strings.Join(toStrings(pol["available_action_types"]), ","), events.ActionARPIsolate) {
		t.Fatalf("available_action_types: %v", pol["available_action_types"])
	}

	status, got := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate})
	if status != 200 || got.State != events.StateActive || got.ActionType != events.ActionARPIsolate {
		t.Fatalf("approve as arp_isolate: %d %+v", status, got)
	}
	agent.mu.Lock()
	cmd := agent.seen[0]
	agent.mu.Unlock()
	if cmd.Type != drivers.CommandIsolate || cmd.MAC != "02:00:00:00:00:31" || cmd.IP != "192.168.1.31" || cmd.TTLSeconds != 3600 {
		t.Fatalf("command sent to the agent: %+v", cmd)
	}

	status, got = h.revert(a.ID, "bob")
	if status != 200 || got.State != events.StateReverted || got.RevertedBy != "bob" {
		t.Fatalf("revert: %d %+v", status, got)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if len(agent.active) != 0 {
		t.Fatalf("the agent still isolates %v", agent.active)
	}
}

func TestARPIsolationRefusedByTheAgent(t *testing.T) {
	h := agentHarness(t)
	agent := newStubAgent(h)
	agent.refuse[drivers.CommandIsolate] = "refused: ip_forward=1 on this host"
	agent.run()
	time.Sleep(30 * time.Millisecond)

	a := h.createPending("02:00:00:00:00:32", "192.168.1.32", "x.example")
	status, got := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate})
	if status != 200 || got.State != events.StateApplyFailed || !strings.Contains(got.FailureReason, "ip_forward") {
		t.Fatalf("a refused isolation: %d %+v", status, got)
	}
	// The controller's own first check: a group MAC never reaches the agent.
	b := h.createPending("ff:ff:ff:ff:ff:ff", "192.168.1.33", "y.example")
	status, got = h.approve(b.ID, map[string]string{"action_type": events.ActionARPIsolate})
	if status != 200 || got.State != events.StateApplyFailed || !strings.Contains(got.FailureReason, "group MAC") {
		t.Fatalf("broadcast target: %d %+v", status, got)
	}
	agent.mu.Lock()
	defer agent.mu.Unlock()
	for _, c := range agent.seen {
		if c.MAC == "ff:ff:ff:ff:ff:ff" {
			t.Fatal("a broadcast isolation reached the agent")
		}
	}
}

// TestAgentInterfaceHasItsOwnCredential: the poll moves actions, so only the
// agent's token may reach it, and the agent's token reaches nothing else.
func TestAgentInterfaceHasItsOwnCredential(t *testing.T) {
	h := agentHarness(t)
	agent := newStubAgent(h)
	for _, tok := range []string{"", testOperatorToken, testIngestToken} {
		agent.token = tok
		if status := agent.poll(); status != http.StatusUnauthorized {
			t.Errorf("poll with %q: %d", tok, status)
		}
	}
	agent.token = testAgentToken
	if status := agent.poll(); status != http.StatusOK {
		t.Fatalf("poll with the agent token: %d", status)
	}
	for _, path := range []string{"/actions/pending", "/policy", "/audit"} {
		if status, _ := h.request(http.MethodGet, path, testAgentToken, nil, nil); status != http.StatusUnauthorized {
			t.Errorf("GET %s with the agent token: %d", path, status)
		}
	}
	if status, _ := h.request(http.MethodPost, "/agent/v1/poll", testAgentToken, []byte("{"), nil); status != http.StatusBadRequest {
		t.Errorf("malformed poll: %d", status)
	}

	// Without an agent token configured the interface does not exist.
	off := newHarness(t, harnessOpts{creds: &credentials{operator: testOperatorToken, ingest: testIngestToken}})
	if status, _ := off.request(http.MethodPost, "/agent/v1/poll", "", []byte("{}"), nil); status != http.StatusNotFound {
		t.Errorf("poll with no agent token configured: %d", status)
	}
}

// TestPollAcceptsWhatTheRealAgentSends pins the bodies apps/netagent
// encodes (proto.Poll): nil slices as null, expires as a time.Time.
func TestPollAcceptsWhatTheRealAgentSends(t *testing.T) {
	h := agentHarness(t)
	for _, body := range []string{
		`{"agent":"soc-node-1","results":null,"active":null}`,
		`{"agent":"soc-node-1","results":[{"id":"i-x-9","ok":false,"error":"refused: target is the gateway"}],` +
			`"active":[{"mac":"aa:bb:cc:dd:ee:77","ip":"192.168.1.77","expires":"2026-11-16T13:00:00.123456789Z"}]}`,
	} {
		status, raw := h.request(http.MethodPost, "/agent/v1/poll", testAgentToken, []byte(body), nil)
		var resp struct {
			Commands []map[string]any `json:"commands"`
		}
		if status != http.StatusOK || json.Unmarshal(raw, &resp) != nil || resp.Commands == nil {
			t.Fatalf("%s: %d %s", body, status, raw)
		}
		for _, c := range resp.Commands {
			id, _ := c["id"].(string)
			if len(id) > 64 || c["type"] != drivers.CommandRelease || c["mac"] != "aa:bb:cc:dd:ee:77" {
				t.Errorf("command the agent cannot use: %v", c)
			}
		}
	}
}

func toStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, x.(string))
		}
	}
	return out
}
