package drivers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

type capturedSwitchCall struct {
	req       SwitchRequest
	signature string
	rawBody   []byte
}

type fakeSwitch struct {
	mu     sync.Mutex
	calls  []capturedSwitchCall
	status int
	srv    *httptest.Server
}

func newFakeSwitch(t *testing.T) *fakeSwitch {
	t.Helper()
	f := &fakeSwitch{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var sr SwitchRequest
		_ = json.Unmarshal(body, &sr)
		f.mu.Lock()
		f.calls = append(f.calls, capturedSwitchCall{
			req:       sr,
			signature: r.Header.Get(events.SignatureHeader),
			rawBody:   body,
		})
		status := f.status
		f.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSwitch) last() capturedSwitchCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return capturedSwitchCall{}
	}
	return f.calls[len(f.calls)-1]
}

// TestSwitchPortSignsRequests is the control that was entirely missing:
// disabling a switch port is the most destructive action in the system and
// used to go out with no authentication at all, so the handler could not tell
// a genuine instruction from a forged one.
func TestSwitchPortSignsRequests(t *testing.T) {
	fs := newFakeSwitch(t)
	d := NewSwitchPortDriver(fs.srv.URL, 0, "switch-secret", nil)

	action := &events.EnforcementAction{
		ID: "ACT-1", TargetMAC: "aa:bb:cc:dd:ee:ff", TargetIP: "192.168.1.50",
	}
	if err := d.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}

	call := fs.last()
	if call.signature == "" {
		t.Fatal("switch request must be signed")
	}
	if err := events.VerifyPayload("switch-secret", call.signature, call.rawBody); err != nil {
		t.Fatalf("signature should verify against the exact body sent: %v", err)
	}
	if err := events.VerifyPayload("other-secret", call.signature, call.rawBody); err == nil {
		t.Fatal("signature must not verify under a different secret")
	}
}

func TestSwitchPortOperationSelection(t *testing.T) {
	action := &events.EnforcementAction{ID: "ACT-1", TargetMAC: "aa:bb:cc:dd:ee:ff"}

	fs := newFakeSwitch(t)
	disable := NewSwitchPortDriver(fs.srv.URL, 0, "s", nil)
	if err := disable.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := fs.last().req.Operation; got != "disable_port" {
		t.Errorf("VLAN 0 should disable the port, got %q", got)
	}

	quarantine := NewSwitchPortDriver(fs.srv.URL, 42, "s", nil)
	if err := quarantine.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}
	call := fs.last()
	if call.req.Operation != "quarantine_vlan" {
		t.Errorf("a configured VLAN should move the port, got %q", call.req.Operation)
	}
	if call.req.QuarantineVLAN != 42 {
		t.Errorf("QuarantineVLAN = %d, want 42", call.req.QuarantineVLAN)
	}
}

func TestSwitchPortRevertRestores(t *testing.T) {
	fs := newFakeSwitch(t)
	d := NewSwitchPortDriver(fs.srv.URL, 42, "s", nil)
	action := &events.EnforcementAction{ID: "ACT-1", TargetMAC: "aa:bb:cc:dd:ee:ff"}

	if err := d.Revert(context.Background(), action); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if got := fs.last().req.Operation; got != "restore" {
		t.Errorf("revert should request restore, got %q", got)
	}
}

// TestSwitchPortRefusesProtectedTarget: the guard must stop the port being
// disabled on infrastructure even if policy somehow let the action through.
func TestSwitchPortRefusesProtectedTarget(t *testing.T) {
	fs := newFakeSwitch(t)
	var g TargetGuard
	g.ProtectIP("192.168.1.1")
	d := NewSwitchPortDriver(fs.srv.URL, 0, "s", &g)

	action := &events.EnforcementAction{
		ID: "ACT-1", TargetMAC: "11:22:33:44:55:66", TargetIP: "192.168.1.1",
	}
	if err := d.Apply(context.Background(), action); err == nil {
		t.Fatal("protected target should be refused")
	}
	if len(fs.calls) != 0 {
		t.Fatal("no webhook call should have been made for a protected target")
	}
}

func TestSwitchPortReportsFailure(t *testing.T) {
	fs := newFakeSwitch(t)
	fs.status = http.StatusInternalServerError
	d := NewSwitchPortDriver(fs.srv.URL, 0, "s", nil)

	action := &events.EnforcementAction{ID: "ACT-1", TargetMAC: "aa:bb:cc:dd:ee:ff"}
	if err := d.Apply(context.Background(), action); err == nil {
		t.Fatal("a non-2xx webhook response must fail Apply")
	}
}

func TestSwitchPortUnsignedWhenNoSecret(t *testing.T) {
	fs := newFakeSwitch(t)
	d := NewSwitchPortDriver(fs.srv.URL, 0, "", nil)
	action := &events.EnforcementAction{ID: "ACT-1", TargetMAC: "aa:bb:cc:dd:ee:ff"}
	if err := d.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if sig := fs.last().signature; sig != "" {
		t.Errorf("no secret configured should mean no signature header, got %q", sig)
	}
}
