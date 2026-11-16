package actions

import (
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
)

func agentIsolate(actionID string) drivers.AgentCommand {
	return drivers.AgentCommand{Type: drivers.CommandIsolate, ActionID: actionID,
		MAC: "02:00:00:00:00:01", IP: "192.168.1.50", TTLSeconds: 600}
}

func TestSinkholeLedger(t *testing.T) {
	s := newStore(t, newClock())
	const rule = "||evil.example^"

	if _, ok, err := s.SinkholeRef("A"); ok || err != nil {
		t.Fatalf("empty ledger: %v %v", ok, err)
	}
	// First seen already present: the operator's rule, not ours.
	if err := s.ClaimSinkholeRule("A", rule, false); err != nil {
		t.Fatal(err)
	}
	if r, refs, known, _ := s.SinkholeRule(rule); !known || r.Owned || refs != 1 {
		t.Fatalf("operator rule: %+v refs=%d known=%v", r, refs, known)
	}
	// Re-adding it ourselves (it had vanished) makes it ours.
	s.ClaimSinkholeRule("B", rule, true)
	if r, refs, _, _ := s.SinkholeRule(rule); !r.Owned || refs != 2 {
		t.Fatalf("after we wrote it: %+v refs=%d", r, refs)
	}
	// A later "already present" claim does not take ownership away.
	s.ClaimSinkholeRule("C", rule, false)
	if r, refs, _, _ := s.SinkholeRule(rule); !r.Owned || refs != 3 {
		t.Fatalf("ownership must stick: %+v refs=%d", r, refs)
	}
	refs, _ := s.SinkholeRefs()
	if len(refs) != 3 || refs[0].ActionID != "A" {
		t.Fatalf("refs: %+v", refs)
	}

	s.ReleaseSinkholeRef("A", true)
	s.ReleaseSinkholeRef("B", true)
	if _, refs, known, _ := s.SinkholeRule(rule); !known || refs != 1 {
		t.Fatal("a rule still referenced was forgotten")
	}
	s.ReleaseSinkholeRef("C", false)
	if _, _, known, _ := s.SinkholeRule(rule); !known {
		t.Fatal("release without forget dropped the rule")
	}
	if rules, _ := s.SinkholeRules(); len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	s.ForgetSinkholeRule(rule)
	if _, refs, known, _ := s.SinkholeRule(rule); known || refs != 0 {
		t.Fatal("forget did not forget")
	}
	if err := s.ReleaseSinkholeRef("nobody", true); err != nil {
		t.Errorf("releasing nothing: %v", err)
	}
}

func TestCommandQueue(t *testing.T) {
	s := newStore(t, newClock())
	a, err := s.EnqueueCommand(agentIsolate("ACT-1"))
	if err != nil || !strings.HasPrefix(a.ID, "i-"+s.Instance()+"-") || a.State != drivers.CommandQueued {
		t.Fatalf("enqueue: %+v %v", a, err)
	}
	b, _ := s.EnqueueCommand(drivers.AgentCommand{Type: drivers.CommandRelease, ActionID: "ACT-2",
		MAC: "02:00:00:00:00:02", IP: "192.168.1.51"})

	if ok, _ := s.CancelCommand(b.ID); !ok {
		t.Fatal("a queued command can be withdrawn")
	}
	taken, _ := s.TakeCommands(10)
	if len(taken) != 1 || taken[0].ID != a.ID || taken[0].State != drivers.CommandSent || taken[0].TTLSeconds != 600 {
		t.Fatalf("take: %+v", taken)
	}
	if again, _ := s.TakeCommands(10); len(again) != 0 {
		t.Fatal("a command was handed out twice")
	}
	if ok, _ := s.CancelCommand(a.ID); ok {
		t.Fatal("a sent command cannot be withdrawn")
	}
	if open, _ := s.OpenCommands(); len(open) != 1 {
		t.Fatalf("open: %+v", open)
	}
	c, changed, err := s.CompleteCommand(a.ID, false, "refused: gateway")
	if err != nil || !changed || c.State != drivers.CommandFailed || c.Error != "refused: gateway" || c.ActionID != "ACT-1" {
		t.Fatalf("complete: %+v %v %v", c, changed, err)
	}
	if _, changed, _ := s.CompleteCommand(a.ID, true, ""); changed {
		t.Fatal("a second result for one command was accepted")
	}
	if _, changed, _ := s.CompleteCommand("i-unknown-1", true, ""); changed {
		t.Fatal("a result for an unknown command was accepted")
	}
	if open, _ := s.OpenCommands(); len(open) != 0 {
		t.Fatalf("open after completion: %+v", open)
	}
}
