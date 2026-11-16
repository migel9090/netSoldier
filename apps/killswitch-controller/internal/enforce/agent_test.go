package enforce

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/libs/events"
)

// agentEnv runs the engine with the netagent-backed driver against a stub
// agent that is just the test calling AgentPoll.
type agentEnv struct {
	*env
	arp *drivers.ARPIsolateDriver
}

// The clock is the test's: a confirmation deadline, the agent grace and a
// TTL pass when the test moves it (passDeadline, clk.Advance). On the wall
// clock, with a 300ms deadline, a confirmation the test sends a moment late
// on a loaded machine lost to the deadline.
func newAgentEnv(t *testing.T) *agentEnv {
	t.Helper()
	en := &env{t: t, clk: &clock{t: time.Now().UTC().Truncate(time.Millisecond)}, path: filepath.Join(t.TempDir(), "ks.db"),
		drv: &scripted{}, cfg: Config{ConfirmTimeout: 300 * time.Millisecond, AgentGrace: 50 * time.Millisecond}}
	ae := &agentEnv{env: en}
	en.open()
	ae.attach()
	return ae
}

// passDeadline moves the clock past the confirmation deadline of id's
// operation until the engine has resolved it. The engine sets the deadline
// from its own goroutine after queuing the command, so a single move could
// come before the deadline is set and leave it in the future.
func (ae *agentEnv) passDeadline(id string) {
	ae.t.Helper()
	give := time.Now().Add(time.Minute)
	for ae.e.Busy(id) {
		if time.Now().After(give) {
			ae.t.Fatalf("%s never gave up waiting for the agent", id)
		}
		ae.clk.Advance(ae.e.cfg.ConfirmTimeout + time.Second)
		ae.e.Wait(context.Background(), id, 300*time.Millisecond)
	}
}

// attach wires the agent driver to the current store (after open or a
// restart).
func (ae *agentEnv) attach() {
	var guard drivers.TargetGuard
	if err := guard.ProtectIP("192.168.1.1"); err != nil {
		ae.t.Fatal(err)
	}
	ae.arp = drivers.NewARPIsolateDriver(ae.s, &guard, nil)
	ae.e = New(ae.s, map[string]drivers.Driver{events.ActionDNSSinkhole: ae.drv, events.ActionARPIsolate: ae.arp}, ae.cfg)
	ae.e.now = ae.clk.Now
}

func (ae *agentEnv) poll(results []drivers.AgentResult, active ...drivers.AgentIsolation) []drivers.AgentCommand {
	ae.t.Helper()
	resp, err := ae.e.AgentPoll(drivers.PollRequest{Agent: "soc-node-1", Results: results, Active: active})
	if err != nil {
		ae.t.Fatal(err)
	}
	return resp.Commands
}

// waitCommands polls until the agent receives n commands.
func (ae *agentEnv) waitCommands(n int, active ...drivers.AgentIsolation) []drivers.AgentCommand {
	ae.t.Helper()
	var got []drivers.AgentCommand
	deadline := time.Now().Add(time.Minute)
	for len(got) < n && time.Now().Before(deadline) {
		got = append(got, ae.poll(nil, active...)...)
		time.Sleep(5 * time.Millisecond)
	}
	if len(got) != n {
		ae.t.Fatalf("agent got %d commands, want %d: %+v", len(got), n, got)
	}
	return got
}

func (ae *agentEnv) approveIsolation(domain string) actions.Record {
	ae.t.Helper()
	r := ae.pending(domain)
	if _, err := ae.e.Approve(r.ID, "alice", events.ActionARPIsolate); err != nil {
		ae.t.Fatal(err)
	}
	return r
}

var device = drivers.AgentIsolation{MAC: "02:00:00:00:00:01", IP: "192.168.1.50"}

// TestIsolationIsActiveOnlyOnceTheAgentConfirms: an action is active only
// once the agent has confirmed it, and its activation is the agent's.
func TestIsolationIsActiveOnlyOnceTheAgentConfirms(t *testing.T) {
	ae := newAgentEnv(t)
	r := ae.pending("x.example")
	if _, err := ae.e.Approve(r.ID, "alice", events.ActionARPIsolate); err == nil {
		t.Fatal("isolation was offered before any agent polled")
	}
	ae.poll(nil)
	if got := ae.e.Available(); strings.Join(got, ",") != "arp_isolate,dns_sinkhole" {
		t.Fatalf("available: %v", got)
	}
	ae.approveIsolation("x.example")
	cmds := ae.waitCommands(1)
	if c := cmds[0]; c.Type != drivers.CommandIsolate || c.MAC != device.MAC || c.IP != device.IP || c.TTLSeconds != 60 {
		t.Fatalf("command %+v", c)
	}
	if got := ae.get(r.ID); got.State != events.StateApproved {
		t.Fatalf("active before the agent confirmed: %s", got.State)
	}
	ae.poll([]drivers.AgentResult{{ID: cmds[0].ID, OK: true}}, device)
	ae.idle()
	got := ae.get(r.ID)
	if got.State != events.StateActive || got.ActivatedAt == nil || got.ExpiresAt == nil {
		t.Fatalf("after confirmation: %+v", got.Action())
	}
	if trail := auditTrail(t, ae.s, r.ID); !strings.HasSuffix(trail, "pending>approved by alice; approved>active by netagent") {
		t.Errorf("audit: %s", trail)
	}
	// A second isolation of the same device is refused: lifting either
	// would lift both.
	other := ae.pending("y.example")
	if _, err := ae.e.Approve(other.ID, "bob", events.ActionARPIsolate); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("second isolation of one device: %v", err)
	}
	// Revert: the release goes out, the operator's revert completes on
	// the agent's word.
	if _, err := ae.e.Revert(context.Background(), r.ID, "bob", "done"); err != nil {
		t.Fatal(err)
	}
	rel := ae.waitCommands(1, device)
	if rel[0].Type != drivers.CommandRelease || ae.get(r.ID).State != events.StateActive {
		t.Fatalf("release: %+v, state %s", rel, ae.get(r.ID).State)
	}
	ae.poll([]drivers.AgentResult{{ID: rel[0].ID, OK: true}})
	ae.idle()
	if got := ae.get(r.ID); got.State != events.StateReverted || got.RevertedBy != "bob" {
		t.Fatalf("after the release: %s by %s", got.State, got.RevertedBy)
	}
}

func TestIsolationRefusedOrUnconfirmedIsApplyFailed(t *testing.T) {
	ae := newAgentEnv(t)
	ae.poll(nil)

	refused := ae.approveIsolation("a.example")
	cmds := ae.waitCommands(1)
	ae.poll([]drivers.AgentResult{{ID: cmds[0].ID, OK: false, Error: "refused: target is the gateway"}})
	ae.idle()
	if got := ae.get(refused.ID); got.State != events.StateApplyFailed || !strings.Contains(got.FailureReason, "gateway") {
		t.Fatalf("refused: %s %q", got.State, got.FailureReason)
	}

	// Fetched but never confirmed: apply_failed, and a release in case it
	// is carried out late.
	silent := ae.approveIsolation("b.example")
	sent := ae.waitCommands(1)
	ae.passDeadline(silent.ID)
	ae.idle()
	if got := ae.get(silent.ID); got.State != events.StateApplyFailed || !strings.Contains(got.FailureReason, "did not confirm") {
		t.Fatalf("unconfirmed: %s %q", got.State, got.FailureReason)
	}
	rel := ae.waitCommands(1)
	if rel[0].Type != drivers.CommandRelease {
		t.Fatalf("no compensating release: %+v", rel)
	}
	// The late confirmation then changes nothing about the action.
	ae.poll([]drivers.AgentResult{{ID: sent[0].ID, OK: true}, {ID: rel[0].ID, OK: true}})
	if got := ae.get(silent.ID); got.State != events.StateApplyFailed {
		t.Fatalf("a late confirmation revived it: %s", got.State)
	}
}

func TestIsolationNeverFetchedIsWithdrawn(t *testing.T) {
	ae := newAgentEnv(t)
	ae.poll(nil)
	r := ae.approveIsolation("a.example")
	ae.passDeadline(r.ID) // the deadline passes with nobody polling
	ae.idle()
	got := ae.get(r.ID)
	if got.State != events.StateApplyFailed {
		t.Fatalf("state %s", got.State)
	}
	if cmds := ae.poll(nil); len(cmds) != 0 {
		t.Fatalf("a withdrawn command was still handed out: %+v", cmds)
	}
}

func TestReleaseRefusedIsRevertFailed(t *testing.T) {
	ae := newAgentEnv(t)
	ae.poll(nil)
	r := ae.approveIsolation("a.example")
	iso := ae.waitCommands(1)
	ae.poll([]drivers.AgentResult{{ID: iso[0].ID, OK: true}}, device)
	ae.idle()

	ae.e.Revert(context.Background(), r.ID, "bob", "done")
	rel := ae.waitCommands(1, device)
	ae.poll([]drivers.AgentResult{{ID: rel[0].ID, OK: false, Error: "rate limited"}}, device)
	ae.idle()
	got := ae.get(r.ID)
	if got.State != events.StateRevertFailed || got.RevertedAt != nil {
		t.Fatalf("a refused release: %s", got.State)
	}
	// The agent's list says it is gone after all: the release took effect.
	ae.clk.Advance(60 * time.Millisecond)
	ae.poll(nil)
	if got := ae.get(r.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorReconcile {
		t.Fatalf("reconciled: %s by %s", got.State, got.RevertedBy)
	}
}

// TestAgentReconciliation: the agent's active list is what is really in
// force.
func TestAgentReconciliation(t *testing.T) {
	ae := newAgentEnv(t)
	ae.poll(nil)
	r := ae.approveIsolation("a.example")
	iso := ae.waitCommands(1)
	ae.poll([]drivers.AgentResult{{ID: iso[0].ID, OK: true}}, device)
	ae.idle()

	// An isolation nobody here owns is released, once.
	stranger := drivers.AgentIsolation{MAC: "02:00:00:00:00:77", IP: "192.168.1.77"}
	cmds := ae.poll(nil, device, stranger)
	if len(cmds) != 1 || cmds[0].Type != drivers.CommandRelease || cmds[0].MAC != stranger.MAC || cmds[0].ActionID != "" {
		t.Fatalf("unowned isolation: %+v", cmds)
	}
	if again := ae.poll(nil, device, stranger); len(again) != 0 {
		t.Fatalf("released twice: %+v", again)
	}
	ae.poll([]drivers.AgentResult{{ID: cmds[0].ID, OK: true}}, device)

	// The agent no longer lists ours (it restarted and restored the ARP
	// entry): the isolation is still wanted, so it is issued again for the
	// rest of its TTL — once, not on every poll.
	ae.clk.Advance(60 * time.Millisecond)
	again := ae.poll(nil)
	if len(again) != 1 || again[0].Type != drivers.CommandIsolate || again[0].MAC != device.MAC ||
		again[0].TTLSeconds < 55 || again[0].TTLSeconds > 61 || again[0].ActionID != r.ID {
		t.Fatalf("re-issue: %+v", again)
	}
	if more := ae.poll(nil); len(more) != 0 {
		t.Fatalf("re-issued twice: %+v", more)
	}
	ae.poll([]drivers.AgentResult{{ID: again[0].ID, OK: true}}, device)
	if got := ae.get(r.ID); got.State != events.StateActive {
		t.Fatalf("after the re-issue was confirmed: %s", got.State)
	}

	// The agent drops it again and now refuses to restore it (isolation was
	// switched off): it is not in force, and the action says so.
	ae.clk.Advance(60 * time.Millisecond)
	third := ae.poll(nil)
	if len(third) != 1 {
		t.Fatalf("second re-issue: %+v", third)
	}
	ae.poll([]drivers.AgentResult{{ID: third[0].ID, OK: false, Error: "refused: isolation is disabled on this agent"}})
	got := ae.get(r.ID)
	if got.State != events.StateReverted || got.RevertedBy != actions.ActorAgent || !strings.Contains(got.Reason, "refused") {
		t.Fatalf("a refused re-issue: %s by %s (%q)", got.State, got.RevertedBy, got.Reason)
	}
	// Results for commands nobody knows are ignored.
	ae.poll([]drivers.AgentResult{{ID: "i-forged-1", OK: true}})
}

// TestIsolationNearItsTTLIsNotReissued: the agent's clock ends an isolation
// a moment before the controller's; that is its TTL, not a loss.
func TestIsolationNearItsTTLIsNotReissued(t *testing.T) {
	ae := newAgentEnv(t)
	ae.e.cfg.AgentGrace = 2 * time.Second
	ae.poll(nil)
	ev := detection("short.example")
	res, err := ae.e.Submit(ev, Decision{ActionType: events.ActionARPIsolate, PolicyRule: "pending", TTLSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	ae.e.Approve(res.Record.ID, "alice", "")
	iso := ae.waitCommands(1)
	ae.poll([]drivers.AgentResult{{ID: iso[0].ID, OK: true}}, device)
	ae.idle()
	ae.clk.Advance(2100 * time.Millisecond) // past the grace, inside it of expiry
	if cmds := ae.poll(nil); len(cmds) != 0 {
		t.Fatalf("an isolation at its TTL was issued again: %+v", cmds)
	}
	if got := ae.get(res.Record.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorTTL {
		t.Fatalf("%s by %s", got.State, got.RevertedBy)
	}
}

func TestPollHandsOutAtMostWhatTheAgentReads(t *testing.T) {
	ae := newAgentEnv(t)
	ae.poll(nil)
	for i := 0; i < 20; i++ {
		ae.arp.Release(fmt.Sprintf("02:00:00:00:01:%02x", i), "192.168.1.200")
	}
	if first := ae.poll(nil); len(first) != maxCommandsPerPoll || maxCommandsPerPoll != 16 {
		t.Fatalf("one poll handed out %d commands; the agent reads 16", len(first))
	}
	if rest := ae.poll(nil); len(rest) != 4 {
		t.Fatalf("the rest: %d", len(rest))
	}
}

// TestIsolationAwaitingConfirmationSurvivesARestart: the deadline is
// persisted, so a confirmation that arrives after a restart still counts.
func TestIsolationAwaitingConfirmationSurvivesARestart(t *testing.T) {
	ae := newAgentEnv(t)
	ae.cfg.ConfirmTimeout = 5 * time.Second
	ae.e.cfg.ConfirmTimeout = 5 * time.Second
	ae.poll(nil)
	r := ae.approveIsolation("a.example")
	cmds := ae.waitCommands(1)
	ae.e.Shutdown(time.Second)

	ae.s.Close()
	ae.open()
	ae.attach()
	ae.e.Recover()
	ae.idle()
	if got := ae.get(r.ID); got.State != events.StateApproved || got.Op != actions.OpApply {
		t.Fatalf("after restart: %s op=%s", got.State, got.Op)
	}
	ae.poll([]drivers.AgentResult{{ID: cmds[0].ID, OK: true}}, device)
	if got := ae.get(r.ID); got.State != events.StateActive {
		t.Fatalf("confirmation after restart: %s", got.State)
	}
}

func TestPollWithoutAgentDriver(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	resp, err := en.e.AgentPoll(drivers.PollRequest{})
	if err != nil || resp.Commands == nil || len(resp.Commands) != 0 {
		t.Fatalf("%+v %v", resp, err)
	}
	var u *UnavailableError
	if err := en.e.checkType(events.ActionARPIsolate); !errors.As(err, &u) {
		t.Fatalf("%v", err)
	}
}
