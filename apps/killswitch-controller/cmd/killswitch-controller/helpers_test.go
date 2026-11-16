package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/enforce"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
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

func criticalIoCEvent() events.DetectionEvent {
	ev := withDomainTarget(testEvent(95, events.SeverityCritical), "evil.com")
	ev.ClientMAC = "aa:bb:cc:dd:ee:ff"
	ev.Source = "threatfox"
	return ev
}

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

const (
	testOperatorToken = "operator-token"
	testIngestToken   = "ingest-token"
	testAgentToken    = "agent-token"
	testWebhookSecret = "wh-secret"
	testActor         = "alice"
)

// harness is the production routing and middleware over a real store and
// engine, with drivers the test chooses.
type harness struct {
	t      *testing.T
	srv    *httptest.Server
	store  *actions.Store
	engine *enforce.Engine
	pol    *policy.Policy
	creds  credentials
}

type harnessOpts struct {
	pol     *policy.Policy            // default: DefaultPolicy, auto-block on, allowlist 192.168.1.1
	drivers map[string]drivers.Driver // default: dns_sinkhole → driver
	driver  drivers.Driver            // the default driver, when drivers is nil
	// driversFor builds the drivers once the store exists (for drivers
	// that keep their state in it).
	driversFor func(*actions.Store) map[string]drivers.Driver
	creds      *credentials // default: the three test tokens
	insecure   bool         // no signature verification
	store      actions.Options
	engine     enforce.Config // DriverTimeout default: a minute
	// wait is responseWait. The default, a minute, is long enough that a
	// request whose driver answers is always answered with the outcome; a
	// test that wants the "still under way" answer holds its driver (see
	// heldDriver) rather than racing a short wait.
	wait time.Duration
	// clock, when set, is the store's and the engine's clock: a test moves
	// it past a TTL or a backoff instead of sleeping through it.
	clock *testClock
}

func newHarness(t *testing.T, o harnessOpts) *harness {
	t.Helper()
	if o.pol == nil {
		o.pol = policy.DefaultPolicy()
		o.pol.AutoBlock = true
		if err := o.pol.Allowlist.AddIP("192.168.1.1"); err != nil {
			t.Fatal(err)
		}
	}
	creds := credentials{operator: testOperatorToken, ingest: testIngestToken, agent: testAgentToken}
	if o.creds != nil {
		creds = *o.creds
	}
	if o.clock != nil {
		o.store.Now, o.engine.Now = o.clock.Now, o.clock.Now
	}
	if o.engine.DriverTimeout == 0 {
		// A driver call the test holds must not run out on a slow machine.
		o.engine.DriverTimeout = time.Minute
	}
	store, err := actions.Open(filepath.Join(t.TempDir(), "ks.db"), o.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if o.driversFor != nil {
		o.drivers = o.driversFor(store)
	}
	if o.drivers == nil {
		d := o.driver
		if d == nil {
			d = &recordingDriver{}
		}
		o.drivers = map[string]drivers.Driver{events.ActionDNSSinkhole: d}
	}
	eng := enforce.New(store, o.drivers, o.engine)
	t.Cleanup(func() { eng.Shutdown(5 * time.Second) })
	wireAutoEnforcement(o.pol, eng)
	s := &server{pol: o.pol, engine: eng, store: store,
		ledger: newEvaluationLedger(store, ledgerRetention(0)), responseWait: o.wait}
	if s.responseWait == 0 {
		s.responseWait = time.Minute
	}
	var verifier *events.SignatureVerifier
	if !o.insecure {
		verifier = &events.SignatureVerifier{Secret: testWebhookSecret}
	}
	h := &harness{t: t, store: store, engine: eng, pol: o.pol, creds: creds}
	h.srv = httptest.NewServer(authMiddleware(creds, verifier, s.routes()))
	t.Cleanup(h.srv.Close)
	return h
}

// request sends a request and returns the status and body.
func (h *harness) request(method, path, token string, body []byte, hdr map[string]string) (int, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type evalResponse struct {
	status    int
	Decision  policy.Decision           `json:"decision"`
	Action    *events.EnforcementAction `json:"action"`
	Duplicate bool                      `json:"duplicate"`
	Error     string                    `json:"error"`
}

// evaluateRaw posts exact bytes to /evaluate with the ingest token.
func (h *harness) evaluateRaw(body []byte, sig string) evalResponse {
	h.t.Helper()
	hdr := map[string]string{}
	if sig != "" {
		hdr[events.SignatureHeader] = sig
	}
	status, raw := h.request(http.MethodPost, "/evaluate", h.creds.ingest, body, hdr)
	out := evalResponse{status: status}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.t.Fatalf("decode %q: %v", raw, err)
	}
	return out
}

// evaluate signs and submits a detection.
func (h *harness) evaluate(ev events.DetectionEvent) evalResponse {
	h.t.Helper()
	body, _ := json.Marshal(ev)
	return h.evaluateRaw(body, events.SignPayload(testWebhookSecret, body))
}

// operate sends an operator mutation as actor.
func (h *harness) operate(path, actor string, body any) (int, actionReply) {
	h.t.Helper()
	data, _ := json.Marshal(body)
	hdr := map[string]string{}
	if actor != "" {
		hdr[actorHeader] = actor
	}
	status, raw := h.request(http.MethodPost, path, h.creds.operator, data, hdr)
	var out actionReply
	_ = json.Unmarshal(raw, &out)
	return status, out
}

type actionReply struct {
	events.EnforcementAction
	Error                string   `json:"error"`
	AvailableActionTypes []string `json:"available_action_types"`
}

func (h *harness) approve(id string, body any) (int, actionReply) {
	return h.operate("/actions/"+id+"/approve", testActor, body)
}

func (h *harness) revert(id, actor string) (int, actionReply) {
	return h.operate("/actions/"+id+"/revert", actor, map[string]string{"reason": "test revert"})
}

// get decodes an operator GET.
func (h *harness) get(path string, dst any) int {
	h.t.Helper()
	status, raw := h.request(http.MethodGet, path, h.creds.operator, nil, nil)
	if dst != nil && status == http.StatusOK {
		if err := json.Unmarshal(raw, dst); err != nil {
			h.t.Fatalf("GET %s: decode %q: %v", path, raw, err)
		}
	}
	return status
}

func (h *harness) list(state string) []events.EnforcementAction {
	h.t.Helper()
	var out []events.EnforcementAction
	if status := h.get("/actions/"+state, &out); status != http.StatusOK {
		h.t.Fatalf("GET /actions/%s: %d", state, status)
	}
	return out
}

func (h *harness) action(id string) events.EnforcementAction {
	h.t.Helper()
	rec, err := h.store.Get(id)
	if err != nil {
		h.t.Fatal(err)
	}
	return rec.Action()
}

// actionCount counts every action in the store.
func (h *harness) actionCount() int {
	h.t.Helper()
	counts, err := h.store.Counts()
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

// createPending stores a pending action directly.
func (h *harness) createPending(mac, ip, domain string) events.EnforcementAction {
	h.t.Helper()
	ev := withDomainTarget(testEvent(60, events.SeverityMedium), domain)
	ev.ClientMAC, ev.ClientIP = mac, ip
	res, err := h.engine.Submit(ev, enforce.Decision{ActionType: events.ActionDNSSinkhole, PolicyRule: "pending", TTLSeconds: 3600})
	if err != nil {
		h.t.Fatal(err)
	}
	return res.Record.Action()
}

func jsonReader(b []byte) io.Reader { return bytes.NewReader(b) }

func (h *harness) idle(id string) {
	h.t.Helper()
	if !h.engine.Wait(context.Background(), id, time.Minute) {
		h.t.Fatalf("%s did not settle", id)
	}
}

// testClock is a clock the test moves.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Now().UTC().Truncate(time.Millisecond)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// heldDriver is a driver whose calls the test answers. Every Apply and
// Revert is handed to the test (next) and blocks until the test answers
// it, so "the driver has not answered yet" is a state the test puts the
// service in, not a race between a sleep in a driver and a wait in a
// handler.
type heldDriver struct {
	recordingDriver
	calls chan *heldCall
	quit  chan struct{}
}

// heldCall is one driver call waiting for the test's answer.
type heldCall struct {
	op     string // "apply" or "revert"
	answer chan error
}

func newHeldDriver(t *testing.T) *heldDriver {
	d := &heldDriver{calls: make(chan *heldCall), quit: make(chan struct{})}
	t.Cleanup(func() { close(d.quit) })
	return d
}

func (d *heldDriver) Apply(ctx context.Context, a *events.EnforcementAction) error {
	if err := d.hold(ctx, "apply"); err != nil {
		return err
	}
	return d.recordingDriver.Apply(ctx, a)
}

func (d *heldDriver) Revert(ctx context.Context, a *events.EnforcementAction) error {
	if err := d.hold(ctx, "revert"); err != nil {
		return err
	}
	return d.recordingDriver.Revert(ctx, a)
}

func (d *heldDriver) Name() string { return "held" }

func (d *heldDriver) hold(ctx context.Context, op string) error {
	c := &heldCall{op: op, answer: make(chan error, 1)}
	select {
	case d.calls <- c:
	case <-ctx.Done():
		return ctx.Err()
	case <-d.quit:
		return errors.New("the test is over")
	}
	select {
	case err := <-c.answer:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-d.quit:
		return errors.New("the test is over")
	}
}

// next returns the driver's next call, which must be op. It stays blocked
// until the test answers it.
func (d *heldDriver) next(t *testing.T, op string) *heldCall {
	t.Helper()
	select {
	case c := <-d.calls:
		if c.op != op {
			t.Fatalf("the driver was asked to %s, want %s", c.op, op)
		}
		return c
	case <-time.After(time.Minute):
		t.Fatalf("no %s reached the driver", op)
		return nil
	}
}

// reply is an answered operator request.
type reply struct {
	status int
	action actionReply
}

// async runs do — a request that waits for the driver the test is playing
// — in its own goroutine, and returns the function that waits for its
// result.
func async[T any](t *testing.T, do func() T) func() T {
	ch := make(chan T, 1)
	go func() { ch <- do() }()
	return func() T {
		t.Helper()
		select {
		case v := <-ch:
			return v
		case <-time.After(time.Minute):
			t.Fatal("the request was never answered")
			var zero T
			return zero
		}
	}
}

// operateAsync is async for an operator request.
func (h *harness) operateAsync(do func() (int, actionReply)) func() reply {
	return async(h.t, func() reply {
		status, a := do()
		return reply{status, a}
	})
}
