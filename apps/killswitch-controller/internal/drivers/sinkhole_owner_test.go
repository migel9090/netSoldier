package drivers

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func sinkAction(id, domain string) *events.EnforcementAction {
	return &events.EnforcementAction{ID: id, BlockedDomain: domain}
}

// TestSinkholeSharedRuleIsReferenceCounted: two actions on one domain;
// reverting one removed the rule while the other still showed active.
func TestSinkholeSharedRuleIsReferenceCounted(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	ctx := context.Background()
	a, b := sinkAction("ACT-A", "evil.example"), sinkAction("ACT-B", "evil.example")
	if err := d.Apply(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := d.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); len(got) != 1 {
		t.Fatalf("one rule for one domain, got %v", got)
	}
	if err := d.Revert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); !slices.Equal(got, []string{"||evil.example^"}) {
		t.Fatalf("reverting A removed the rule B still needs: %v", got)
	}
	if err := d.Revert(ctx, b); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); len(got) != 0 {
		t.Fatalf("the last reference is gone but the rule stays: %v", got)
	}
}

// TestSinkholeNeverRemovesARuleItDidNotAdd: an operator rule that already
// existed was deleted by our apply-then-revert.
func TestSinkholeNeverRemovesARuleItDidNotAdd(t *testing.T) {
	ag := newFakeAdGuard(t, "||ads.example^", "@@||bank.example^")
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	ctx := context.Background()
	a := sinkAction("ACT-A", "ads.example")
	if err := d.Apply(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := d.Revert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); !slices.Equal(got, []string{"||ads.example^", "@@||bank.example^"}) {
		t.Fatalf("the operator's rules must survive our apply and revert: %v", got)
	}
	if writes := ag.writeCount(); writes != 0 {
		t.Errorf("nothing needed writing, but AdGuard was written %d times", writes)
	}
}

// TestSinkholeFailsClosedWithoutUserRules: a status reply without
// user_rules was read as an empty list, and the next apply overwrote every
// operator rule.
func TestSinkholeFailsClosedWithoutUserRules(t *testing.T) {
	for name, body := range map[string]string{
		"key absent":        `{"enabled":true}`,
		"not a list":        `{"user_rules":"||x^"}`,
		"not json":          `<html>proxy error</html>`,
		"list of non-names": `{"user_rules":[1,2]}`,
	} {
		t.Run(name, func(t *testing.T) {
			ag := newFakeAdGuard(t, "||operator-rule.example^")
			ag.inject(func() { ag.status = body })
			d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
			err := d.Apply(context.Background(), sinkAction("ACT-A", "evil.example"))
			if err == nil || !errors.Is(err, ErrNotApplied) {
				t.Fatalf("got %v, want a refusal that changed nothing", err)
			}
			if ag.writeCount() != 0 || !slices.Equal(ag.current(), []string{"||operator-rule.example^"}) {
				t.Fatalf("AdGuard was written: %v", ag.current())
			}
		})
	}
	// null is how AdGuard encodes a list that was never set: empty.
	ag := newFakeAdGuard(t)
	ag.inject(func() { ag.status = `{"enabled":true,"user_rules":null}` })
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	if err := d.Apply(context.Background(), sinkAction("ACT-A", "evil.example")); err != nil {
		t.Fatalf("null user_rules: %v", err)
	}
}

// TestSinkholeApplyErrorsSayWhetherAnythingChanged: the controller undoes
// an apply only when it might have taken effect.
func TestSinkholeApplyErrorsSayWhetherAnythingChanged(t *testing.T) {
	ctx := context.Background()

	ag := newFakeAdGuard(t)
	ag.inject(func() { ag.failGets = 1 })
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	if err := d.Apply(ctx, sinkAction("ACT-A", "evil.example")); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("a failed read changes nothing: %v", err)
	}
	if err := d.Apply(ctx, sinkAction("ACT-B", "co.uk")); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("an invalid domain changes nothing: %v", err)
	}

	// The write is answered 502 but AdGuard stored it anyway: the error
	// must not claim nothing changed, and the claim lets Revert clean up.
	ag = newFakeAdGuard(t)
	ag.inject(func() { ag.failSets, ag.applyThen = 1, true })
	d = NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	a := sinkAction("ACT-A", "evil.example")
	err := d.Apply(ctx, a)
	if err == nil || errors.Is(err, ErrNotApplied) {
		t.Fatalf("a failed write is ambiguous, got %v", err)
	}
	if got := ag.current(); len(got) != 1 {
		t.Fatalf("setup: the rule should have been stored: %v", got)
	}
	if err := d.Revert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); len(got) != 0 {
		t.Fatalf("the compensating revert left the rule: %v", got)
	}
}

// TestSinkholeRevertFailureKeepsTheClaim: a revert that fails leaves the
// action holding its rule, so the retry still knows what to remove.
func TestSinkholeRevertFailureKeepsTheClaim(t *testing.T) {
	ctx := context.Background()
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", nil)
	a := sinkAction("ACT-A", "evil.example")
	if err := d.Apply(ctx, a); err != nil {
		t.Fatal(err)
	}
	ag.inject(func() { ag.failSets = 2 })
	for i := 0; i < 2; i++ {
		if err := d.Revert(ctx, a); err == nil {
			t.Fatalf("revert %d: a 502 must fail the revert", i)
		}
	}
	if got := ag.current(); len(got) != 1 {
		t.Fatalf("setup: the rule should still be there: %v", got)
	}
	if err := d.Revert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got := ag.current(); len(got) != 0 {
		t.Fatalf("the retry did not remove the rule: %v", got)
	}
	if err := d.Revert(ctx, a); err != nil {
		t.Fatalf("reverting twice: %v", err)
	}
}

func TestSinkholeReconcile(t *testing.T) {
	ctx := context.Background()
	ag := newFakeAdGuard(t, "||operator.example^")
	ledger := newMemoryLedger()
	d := NewSinkholeDriver(ag.srv.URL, "u", "p", ledger)
	for _, a := range []*events.EnforcementAction{
		sinkAction("ACT-keep", "keep.example"),
		sinkAction("ACT-gone", "gone.example"),
		sinkAction("ACT-stale", "stale.example"),
		sinkAction("ACT-busy", "busy.example"),
		sinkAction("ACT-op", "operator.example"),
	} {
		if err := d.Apply(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	// gone.example vanishes from AdGuard; adopt.example appears there by
	// someone else's hand.
	ag.mu.Lock()
	ag.rules = slices.DeleteFunc(ag.rules, func(r string) bool { return r == "||gone.example^" })
	ag.rules = append(ag.rules, "||adopt.example^")
	ag.mu.Unlock()

	enforced := []SinkholeClaim{
		{ActionID: "ACT-keep", Domain: "keep.example"},
		{ActionID: "ACT-gone", Domain: "gone.example"},
		{ActionID: "ACT-adopt", Domain: "adopt.example"},
		{ActionID: "ACT-lost", Domain: "lost.example"},
	}
	inFlight := func(id string) bool { return id == "ACT-busy" }

	// AdGuard unreadable: nothing changes.
	ag.inject(func() { ag.failGets = 1 })
	if _, err := d.Reconcile(ctx, enforced, inFlight); err == nil {
		t.Fatal("reconciliation must fail closed when AdGuard cannot be read")
	}

	rep, err := d.Reconcile(ctx, enforced, inFlight)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(rep.Missing)
	if !slices.Equal(rep.Missing, []string{"ACT-gone", "ACT-lost"}) {
		t.Errorf("missing: %v", rep.Missing)
	}
	if !slices.Equal(rep.StaleRefs, []string{"ACT-op", "ACT-stale"}) {
		t.Errorf("stale: %v", rep.StaleRefs)
	}
	if !slices.Equal(rep.Removed, []string{"||stale.example^"}) {
		t.Errorf("removed: %v (the operator's rule must never be)", rep.Removed)
	}
	if !slices.Equal(rep.Adopted, []string{"ACT-adopt"}) {
		t.Errorf("adopted: %v", rep.Adopted)
	}
	got := ag.current()
	slices.Sort(got)
	want := []string{"||adopt.example^", "||busy.example^", "||keep.example^", "||operator.example^"}
	if !slices.Equal(got, want) {
		t.Errorf("AdGuard after reconciliation: %v, want %v", got, want)
	}
	// An adopted rule is not ours: reverting its action leaves it.
	if err := d.Revert(ctx, sinkAction("ACT-adopt", "adopt.example")); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ag.current(), "||adopt.example^") {
		t.Error("an adopted rule was removed")
	}
	// A second pass finds nothing more to do.
	rep, err = d.Reconcile(ctx, enforced[:1], inFlight)
	if err != nil || len(rep.Removed)+len(rep.StaleRefs)+len(rep.Missing) != 0 {
		t.Errorf("second pass: %+v %v", rep, err)
	}
	if rules, _ := ledger.SinkholeRules(); len(rules) != 2 {
		t.Errorf("ledger keeps %v", rules)
	}
	if strings.Contains(strings.Join(ag.current(), ","), "stale") {
		t.Error("orphan survived")
	}
}
