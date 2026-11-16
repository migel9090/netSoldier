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

// fetch polls until the agent is handed a new command of type typ for mac,
// and returns it. The engine queues a command from its own goroutine after
// answering the request that caused it, so a single poll right after that
// request can come too early.
func (a *stubAgent) fetch(typ, mac string) drivers.AgentCommand {
	a.t.Helper()
	a.mu.Lock()
	from := len(a.seen)
	a.mu.Unlock()
	deadline := time.Now().Add(time.Minute)
	for {
		a.poll()
		a.mu.Lock()
		for _, c := range a.seen[from:] {
			if c.Type == typ && c.MAC == mac {
				a.mu.Unlock()
				return c
			}
		}
		a.mu.Unlock()
		if time.Now().After(deadline) {
			a.t.Fatalf("no %s for %s was handed to the agent", typ, mac)
		}
		time.Sleep(5 * time.Millisecond)
	}
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
	return agentHarnessWith(t, time.Minute, 0)
}

// agentHarnessWith sets how long an isolation waits for the agent's
// confirmation and how long a request waits for an outcome (0: the
// harness default). A confirmation the agent is meant to give must have a
// minute, not a moment: the agent's poll loop runs on the same busy
// machine.
func agentHarnessWith(t *testing.T, confirm, wait time.Duration) *harness {
	t.Helper()
	return newHarness(t, harnessOpts{
		engine: enforce.Config{ConfirmTimeout: confirm},
		wait:   wait,
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
	agent.poll() // seen: isolation is offered from now on
	agent.run()
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

// TestInFlightNamesTheOutstandingOperation: an action whose release the
// netagent has not confirmed yet was served exactly like an active block
// nobody was lifting, and an isolation waiting for the agent like any
// approved action. in_flight says which operation is outstanding, on every
// read, and is gone once it is answered.
//
// Nothing here races a clock: an operation waiting for the agent cannot
// finish before the test polls as the agent, so the short response wait
// always runs out first.
func TestInFlightNamesTheOutstandingOperation(t *testing.T) {
	h := agentHarnessWith(t, time.Minute, 50*time.Millisecond)
	agent := newStubAgent(h)
	agent.poll() // seen: isolation is available
	a := h.createPending("02:00:00:00:00:34", "192.168.1.34", "x.example")
	if a.InFlight != "" {
		t.Fatalf("a pending action has nothing in flight: %q", a.InFlight)
	}

	inFlight := func(want string) {
		t.Helper()
		var got events.EnforcementAction
		if status := h.get("/actions/"+a.ID, &got); status != http.StatusOK || got.InFlight != want {
			t.Errorf("GET /actions/%s: %d in_flight %q, want %q", a.ID, status, got.InFlight, want)
		}
	}

	status, got := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate})
	if status != http.StatusAccepted || got.State != events.StateApproved || got.InFlight != events.OperationApply {
		t.Fatalf("approve awaiting the agent: %d %s in_flight %q", status, got.State, got.InFlight)
	}
	inFlight(events.OperationApply)

	agent.fetch(drivers.CommandIsolate, "02:00:00:00:00:34")
	agent.poll() // reports it done
	if st := h.action(a.ID).State; st != events.StateActive {
		t.Fatalf("after the agent confirmed: %s", st)
	}
	inFlight("")

	status, got = h.revert(a.ID, "bob")
	if status != http.StatusAccepted || got.State != events.StateActive || got.InFlight != events.OperationRevert {
		t.Fatalf("revert awaiting the agent: %d %s in_flight %q", status, got.State, got.InFlight)
	}
	inFlight(events.OperationRevert)
	if l := h.list("active"); len(l) != 1 || l[0].InFlight != events.OperationRevert {
		t.Errorf("/actions/active must show the release under way: %+v", l)
	}

	agent.fetch(drivers.CommandRelease, "02:00:00:00:00:34")
	agent.poll() // reports it done
	h.idle(a.ID)
	if st := h.action(a.ID).State; st != events.StateReverted {
		t.Fatalf("after the agent confirmed the release: %s", st)
	}
	inFlight("")
	if l := h.list("history"); len(l) != 1 || l[0].InFlight != "" {
		t.Errorf("a finished action has nothing in flight: %+v", l)
	}
}

// TestIsolationAuditNamesApproverAndConfirmer pins the attribution rule of
// the actions package documentation for a deferred driver: the approval
// names the operator, the apply's outcome names the netagent (it confirmed,
// refused, or stayed silent past the deadline), and the revert's outcome
// names the operator who asked for it although the agent confirmed it. The
// synchronous counterpart is TestAuditTrailIsCompleteAndAttributable.
//
// The isolation that goes unconfirmed runs in a controller of its own with
// a short confirmation deadline, and nothing polls it; the ones the agent
// answers get a deadline they cannot miss. One controller for all three
// made the confirmed isolation race the deadline meant for the silent one.
func TestIsolationAuditNamesApproverAndConfirmer(t *testing.T) {
	trail := func(h *harness, id string) string {
		t.Helper()
		var entries []actions.AuditEntry
		if status := h.get("/audit?action_id="+id, &entries); status != http.StatusOK {
			t.Fatalf("GET /audit: %d", status)
		}
		var steps []string
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i]
			steps = append(steps, e.FromState+">"+e.ToState+":"+e.Actor)
		}
		return strings.Join(steps, " ")
	}
	isolate := func(h *harness, mac, ip string) string {
		t.Helper()
		a := h.createPending(mac, ip, "x.example")
		if status, _ := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate}); status != http.StatusOK {
			t.Fatalf("approve %s: %d", a.ID, status)
		}
		return a.ID
	}

	quiet := agentHarnessWith(t, 300*time.Millisecond, 0)
	newStubAgent(quiet).poll() // seen, but not polling: the isolation goes unconfirmed
	silent := isolate(quiet, "02:00:00:00:00:35", "192.168.1.35")

	h := agentHarness(t)
	agent := newStubAgent(h)
	agent.poll()
	agent.run()
	confirmed := isolate(h, "02:00:00:00:00:36", "192.168.1.36")
	if status, _ := h.revert(confirmed, "bob"); status != http.StatusOK {
		t.Fatalf("revert: %d", status)
	}
	agent.mu.Lock()
	agent.refuse[drivers.CommandIsolate] = "refused: target is the gateway"
	agent.mu.Unlock()
	refused := isolate(h, "02:00:00:00:00:37", "192.168.1.37")

	for _, c := range []struct {
		h        *harness
		id, want string
	}{
		{quiet, silent, ">pending:auto-policy pending>approved:alice approved>apply_failed:netagent"},
		{h, confirmed, ">pending:auto-policy pending>approved:alice approved>active:netagent active>reverted:bob"},
		{h, refused, ">pending:auto-policy pending>approved:alice approved>apply_failed:netagent"},
	} {
		if got := trail(c.h, c.id); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.id, got, c.want)
		}
	}
	if a := h.action(confirmed); a.ApprovedBy != testActor || a.RevertedBy != "bob" {
		t.Errorf("approved_by %q reverted_by %q, want the operators", a.ApprovedBy, a.RevertedBy)
	}
}

func TestARPIsolationRefusedByTheAgent(t *testing.T) {
	h := agentHarness(t)
	agent := newStubAgent(h)
	agent.refuse[drivers.CommandIsolate] = "refused: ip_forward=1 on this host"
	agent.poll() // seen: isolation is offered from now on
	agent.run()

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
