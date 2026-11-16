//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// These run the real killswitch binary through the failures the state
// machine exists for: a crash with a block in force, an AdGuard outage
// during a revert, a double approve, a late approval, a shared rule and
// an operator's own rule — and read the audit trail back.

var ksBinOnce struct {
	sync.Once
	path string
	err  error
}

// killswitchBinary builds the binary once for every test in this file.
func killswitchBinary(t *testing.T) string {
	t.Helper()
	ksBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ks-e2e-")
		if err != nil {
			ksBinOnce.err = err
			return
		}
		ksBinOnce.path = filepath.Join(dir, "killswitch-controller")
		cmd := exec.Command("go", "build", "-o", ksBinOnce.path, "./cmd/killswitch-controller")
		cmd.Dir = filepath.Join(repoRoot(t), "apps", "killswitch-controller")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
		if out, err := cmd.CombinedOutput(); err != nil {
			ksBinOnce.err = fmt.Errorf("build: %v\n%s", err, out)
		}
	})
	if ksBinOnce.err != nil {
		t.Fatal(ksBinOnce.err)
	}
	return ksBinOnce.path
}

// chaosAdGuard is AdGuard Home's filtering API with failure injection.
type chaosAdGuard struct {
	url      string
	mu       sync.Mutex
	rules    []string
	writes   int
	failSets int           // answer this many writes 502, storing nothing
	setDelay time.Duration // answer writes this late
}

func startChaosAdGuard(t *testing.T, rules ...string) *chaosAdGuard {
	t.Helper()
	a := &chaosAdGuard{rules: append([]string{}, rules...)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /control/filtering/status", func(w http.ResponseWriter, _ *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"enabled": true, "user_rules": append([]string{}, a.rules...)})
	})
	mux.HandleFunc("POST /control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Rules []string `json:"rules"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		a.mu.Lock()
		if a.failSets > 0 {
			a.failSets--
			a.mu.Unlock()
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		a.rules, a.writes = body.Rules, a.writes+1
		delay := a.setDelay
		a.mu.Unlock()
		time.Sleep(delay)
	})
	ln := listenTCP(t)
	a.url = "http://" + ln.Addr().String()
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return a
}

func (a *chaosAdGuard) has(rule string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Contains(a.rules, rule)
}

func (a *chaosAdGuard) snapshot() ([]string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string{}, a.rules...), a.writes
}

func (a *chaosAdGuard) inject(fn func(a *chaosAdGuard)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a)
}

// ksInstance is one killswitch process that the test may kill outright.
type ksInstance struct {
	addr string
	cmd  *exec.Cmd
}

func ksEnv(addr, agURL, db string, extra map[string]string) map[string]string {
	env := map[string]string{
		"LISTEN_ADDR":                addr,
		"KILLSWITCH_DB_PATH":         db,
		"ADGUARD_URL":                agURL,
		"ADGUARD_USER":               "admin",
		"ADGUARD_PASSWORD":           "test",
		"KILLSWITCH_API_KEY":         e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN":    e2eIngestToken,
		"WEBHOOK_SECRET":             e2eWebhookSecret,
		"ALLOWLIST_IPS":              "192.168.1.1",
		"KILLSWITCH_REAPER_INTERVAL": "250ms",
		"CLICKHOUSE_URL":             "",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func startKS(t *testing.T, env map[string]string) *ksInstance {
	t.Helper()
	cmd := exec.Command(killswitchBinary(t))
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ks := &ksInstance{addr: env["LISTEN_ADDR"], cmd: cmd}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	})
	waitHealthy(t, "http://"+ks.addr+"/healthz")
	return ks
}

// crash kills the process without letting it shut down.
func (k *ksInstance) crash(t *testing.T) {
	t.Helper()
	if err := k.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = k.cmd.Wait()
}

type ksAction struct {
	events.EnforcementAction
	Error string `json:"error"`
}

// operate sends an operator mutation as actor and returns status and action.
func (k *ksInstance) operate(t *testing.T, id, verb, actor string, body any) (int, ksAction) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "http://"+k.addr+"/actions/"+id+"/"+verb, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+e2eAPIKey)
	req.Header.Set("X-Netsoldier-Actor", actor)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", verb, id, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var a ksAction
	_ = json.Unmarshal(raw, &a)
	return resp.StatusCode, a
}

func (k *ksInstance) action(t *testing.T, id string) events.EnforcementAction {
	t.Helper()
	var a events.EnforcementAction
	httpGetJSON(t, "http://"+k.addr+"/actions/"+id, &a)
	return a
}

func (k *ksInstance) evaluate(t *testing.T, ev events.DetectionEvent) *events.EnforcementAction {
	t.Helper()
	var res struct {
		Action *events.EnforcementAction `json:"action"`
	}
	postAuthedJSON(t, "http://"+k.addr+"/evaluate", e2eIngestToken, ev, &res)
	if res.Action == nil {
		t.Fatalf("no action for %s", ev.ID)
	}
	return res.Action
}

func clientEvent(domain, client string, confidence int, severity string) events.DetectionEvent {
	ev := v2Event(domain, confidence, severity)
	ev.ClientIP = client
	return ev
}

// waitState polls the action until it reaches state, failing the test at
// the deadline. check runs on every observation before that.
func (k *ksInstance) waitState(t *testing.T, id, state string, within time.Duration,
	check func(events.EnforcementAction)) events.EnforcementAction {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		a := k.action(t, id)
		if check != nil {
			check(a)
		}
		if a.State == state {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is %s after %s, want %s (%s)", id, a.State, within, state, a.FailureReason)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestKillswitchCrashKeepsTheBlockE2E: the store was in memory, so a crash
// lost every record of what was enforced — the rule stayed in AdGuard for
// good and nothing would ever revert it.
func TestKillswitchCrashKeepsTheBlockE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	db := ksDBPath(t)
	addr := freeAddr(t)
	env := ksEnv(addr, ag.url, db, map[string]string{"POLICY_DEFAULT_TTL": "6"})
	ks := startKS(t, env)

	a := ks.evaluate(t, clientEvent("crash-c2.example", "192.168.1.61", 97, events.SeverityCritical))
	if a.State != events.StateActive || !ag.has("||crash-c2.example^") || a.ExpiresAt == nil {
		t.Fatalf("setup: %+v", a)
	}
	ks.crash(t)

	ks = startKS(t, env)
	active := listActions(t, ks.addr, "active")
	if len(active) != 1 || active[0].ID != a.ID || active[0].ExpiresAt == nil || !active[0].ExpiresAt.Equal(*a.ExpiresAt) {
		t.Fatalf("after the crash the block must still be known, with its expiry: %+v", active)
	}
	if !ag.has("||crash-c2.example^") {
		t.Fatal("start-up reconciliation removed a rule that is still wanted")
	}
	// It lasts until expires_at and is reverted then.
	final := ks.waitState(t, a.ID, events.StateReverted, 15*time.Second, func(cur events.EnforcementAction) {
		if cur.State != events.StateActive && time.Now().Before(a.ExpiresAt.Add(-500*time.Millisecond)) {
			t.Fatalf("ended before its TTL: %s", cur.State)
		}
	})
	if final.RevertedBy != "ttl" || ag.has("||crash-c2.example^") {
		t.Fatalf("after its TTL: reverted_by=%q rule present=%v", final.RevertedBy, ag.has("||crash-c2.example^"))
	}
}

// TestKillswitchRevertDuringAdGuardOutageE2E: a 502 during a manual revert
// made the action "failed"; the reaper never retried, a second revert said
// "reverted" without calling AdGuard, and the block was permanent.
func TestKillswitchRevertDuringAdGuardOutageE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	ks := startKS(t, ksEnv(freeAddr(t), ag.url, ksDBPath(t), map[string]string{
		"KILLSWITCH_REVERT_RETRY_BASE": "500ms",
		"KILLSWITCH_REVERT_RETRY_MAX":  "1s",
	}))
	a := ks.evaluate(t, clientEvent("outage-c2.example", "192.168.1.62", 97, events.SeverityCritical))
	if a.State != events.StateActive {
		t.Fatalf("setup: %+v", a)
	}

	ag.inject(func(a *chaosAdGuard) { a.failSets = 3 })
	status, got := ks.operate(t, a.ID, "revert", "alice", map[string]string{"reason": "false positive"})
	if status != http.StatusBadGateway || got.State != events.StateRevertFailed {
		t.Fatalf("revert during the outage: %d %+v", status, got)
	}
	if failed := listActions(t, ks.addr, "failed"); len(failed) != 1 || failed[0].ID != a.ID {
		t.Fatalf("/actions/failed: %+v", failed)
	}
	// Never reported reverted while the rule exists; retried until it is gone.
	final := ks.waitState(t, a.ID, events.StateReverted, 20*time.Second, func(cur events.EnforcementAction) {
		if cur.State == events.StateReverted && ag.has("||outage-c2.example^") {
			t.Fatal("reported reverted while the rule is still in AdGuard")
		}
		if cur.State != events.StateReverted && !events.IsEnforcedState(cur.State) {
			t.Fatalf("left the enforced states without reverting: %s", cur.State)
		}
	})
	if ag.has("||outage-c2.example^") || final.RevertedBy != "ttl" {
		t.Fatalf("after recovery: rule present=%v reverted_by=%q", ag.has("||outage-c2.example^"), final.RevertedBy)
	}
}

// TestKillswitchConcurrentApproveE2E: two approvals at once must apply once.
func TestKillswitchConcurrentApproveE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	ag.inject(func(a *chaosAdGuard) { a.setDelay = 300 * time.Millisecond })
	ks := startKS(t, ksEnv(freeAddr(t), ag.url, ksDBPath(t), nil))
	a := ks.evaluate(t, clientEvent("double.example", "192.168.1.63", 75, events.SeverityMedium))
	if a.State != events.StatePending {
		t.Fatalf("setup: %+v", a)
	}

	var wg sync.WaitGroup
	results := make([]string, 2)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, got := ks.operate(t, a.ID, "approve", "alice", nil)
			results[i] = fmt.Sprintf("%d/%s", status, got.State)
		}()
	}
	wg.Wait()
	ks.waitState(t, a.ID, events.StateActive, 10*time.Second, nil)
	if _, writes := ag.snapshot(); writes != 1 {
		t.Fatalf("AdGuard was written %d times for one approval (answers %v)", writes, results)
	}
	for _, r := range results {
		if r != "200/active" && r != "202/approved" {
			t.Errorf("approve answer %s", r)
		}
	}
}

// TestKillswitchLateApprovalLastsItsTTLE2E: expires_at was computed at
// creation, so an action approved after its TTL was reverted at once.
func TestKillswitchLateApprovalLastsItsTTLE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	ks := startKS(t, ksEnv(freeAddr(t), ag.url, ksDBPath(t), map[string]string{"POLICY_DEFAULT_TTL": "3"}))
	a := ks.evaluate(t, clientEvent("late.example", "192.168.1.64", 75, events.SeverityMedium))
	time.Sleep(4 * time.Second) // longer than the TTL, counted from creation

	status, got := ks.operate(t, a.ID, "approve", "alice", nil)
	if status != 200 || got.State != events.StateActive || got.ActivatedAt == nil || got.ExpiresAt == nil {
		t.Fatalf("approve: %d %+v", status, got)
	}
	if d := got.ExpiresAt.Sub(*got.ActivatedAt); d != 3*time.Second {
		t.Fatalf("expires_at - activated_at = %s, want the full TTL", d)
	}
	time.Sleep(2 * time.Second)
	if cur := ks.action(t, a.ID); cur.State != events.StateActive || !ag.has("||late.example^") {
		t.Fatalf("ended before its TTL: %s", cur.State)
	}
	ks.waitState(t, a.ID, events.StateReverted, 10*time.Second, nil)
}

// TestKillswitchSharedRuleE2E: two actions on one domain; reverting one
// removed the rule while the other still showed active.
func TestKillswitchSharedRuleE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	ks := startKS(t, ksEnv(freeAddr(t), ag.url, ksDBPath(t), nil))
	first := ks.evaluate(t, clientEvent("shared-c2.example", "192.168.1.65", 97, events.SeverityCritical))
	second := ks.evaluate(t, clientEvent("shared-c2.example", "192.168.1.66", 97, events.SeverityCritical))
	if first.ID == second.ID || first.State != events.StateActive || second.State != events.StateActive {
		t.Fatalf("setup: %+v / %+v", first, second)
	}
	if rules, _ := ag.snapshot(); len(rules) != 1 {
		t.Fatalf("one domain, rules %v", rules)
	}
	if status, got := ks.operate(t, first.ID, "revert", "alice", nil); status != 200 || got.State != events.StateReverted {
		t.Fatalf("revert first: %d %+v", status, got)
	}
	if !ag.has("||shared-c2.example^") || ks.action(t, second.ID).State != events.StateActive {
		t.Fatal("reverting one action removed the rule the other still enforces")
	}
	if status, _ := ks.operate(t, second.ID, "revert", "alice", nil); status != 200 || ag.has("||shared-c2.example^") {
		t.Fatalf("the last reference went but the rule stayed (%d)", status)
	}
}

// TestKillswitchKeepsOperatorRulesE2E: a rule the operator already had was
// deleted by our apply-then-revert.
func TestKillswitchKeepsOperatorRulesE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	operator := []string{"||ads.example^", "@@||bank.example^"}
	ag := startChaosAdGuard(t, operator...)
	db := ksDBPath(t)
	env := ksEnv(freeAddr(t), ag.url, db, nil)
	ks := startKS(t, env)

	a := ks.evaluate(t, clientEvent("ads.example", "192.168.1.67", 97, events.SeverityCritical))
	b := ks.evaluate(t, clientEvent("mine.example", "192.168.1.67", 97, events.SeverityCritical))
	if a.State != events.StateActive || b.State != events.StateActive {
		t.Fatalf("setup: %s %s", a.State, b.State)
	}
	// A restart in between: ownership is durable.
	ks.crash(t)
	ks = startKS(t, env)
	ks.operate(t, a.ID, "revert", "alice", nil)
	ks.operate(t, b.ID, "revert", "alice", nil)
	rules, _ := ag.snapshot()
	if !slices.Equal(rules, operator) {
		t.Fatalf("AdGuard after our apply and revert: %v, want the operator's rules untouched %v", rules, operator)
	}
}

// TestKillswitchAuditTrailE2E reads one full lifecycle back through GET
// /audit: every transition, attributed to who caused it.
func TestKillswitchAuditTrailE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ag := startChaosAdGuard(t)
	ks := startKS(t, ksEnv(freeAddr(t), ag.url, ksDBPath(t), map[string]string{"POLICY_DEFAULT_TTL": "2"}))

	manual := ks.evaluate(t, clientEvent("audit-manual.example", "192.168.1.68", 75, events.SeverityMedium))
	rejected := ks.evaluate(t, clientEvent("audit-reject.example", "192.168.1.68", 75, events.SeverityMedium))
	auto := ks.evaluate(t, clientEvent("audit-auto.example", "192.168.1.68", 97, events.SeverityCritical))

	ks.operate(t, manual.ID, "approve", "alice", map[string]string{"approved_by": "mallory"})
	ks.operate(t, manual.ID, "revert", "bob", map[string]string{"reason": "false positive"})
	ks.operate(t, rejected.ID, "reject", "carol", map[string]string{"reason": "known printer"})
	ks.waitState(t, auto.ID, events.StateReverted, 10*time.Second, nil)

	var entries []struct {
		Seq           int64     `json:"seq"`
		Timestamp     time.Time `json:"timestamp"`
		ActionID      string    `json:"action_id"`
		FromState     string    `json:"from_state"`
		ToState       string    `json:"to_state"`
		Actor         string    `json:"actor"`
		Reason        string    `json:"reason"`
		DetectionID   string    `json:"detection_id"`
		TargetIP      string    `json:"target_ip"`
		ActionType    string    `json:"action_type"`
		BlockedDomain string    `json:"blocked_domain"`
		PolicyRule    string    `json:"policy_rule"`
	}
	httpGetJSON(t, "http://"+ks.addr+"/audit?limit=100", &entries)
	trail := map[string][]string{}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		trail[e.ActionID] = append(trail[e.ActionID], e.FromState+">"+e.ToState+":"+e.Actor)
		if e.DetectionID == "" || e.TargetIP != "192.168.1.68" || e.BlockedDomain == "" || e.PolicyRule == "" ||
			e.ActionType != events.ActionDNSSinkhole || e.Timestamp.IsZero() {
			t.Errorf("incomplete audit entry: %+v", e)
		}
	}
	want := map[string]string{
		manual.ID:   ">pending:auto-policy pending>approved:alice approved>active:alice active>reverted:bob",
		rejected.ID: ">pending:auto-policy pending>rejected:carol",
		auto.ID:     ">approved:auto-policy approved>active:auto-policy active>reverted:ttl",
	}
	for id, w := range want {
		if got := strings.Join(trail[id], " "); got != w {
			t.Errorf("audit trail of %s:\n got %s\nwant %s", id, got, w)
		}
	}
	if strings.Contains(fmt.Sprint(trail), "mallory") {
		t.Error("an identity from a request body reached the audit log")
	}
}
