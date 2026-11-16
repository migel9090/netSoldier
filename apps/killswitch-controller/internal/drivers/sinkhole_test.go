package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

// fakeAdGuard is a minimal stand-in for AdGuard Home's filtering API that
// records every rule list it is asked to store.
type fakeAdGuard struct {
	mu     sync.Mutex
	rules  []string
	writes int
	srv    *httptest.Server

	// Failure injection.
	failGets  int  // answer this many status reads with 502
	failSets  int  // answer this many writes with 502, storing nothing
	applyThen bool // a failing write still stores the rules (the reply is what fails)
	status    string
}

func newFakeAdGuard(t *testing.T, initial ...string) *fakeAdGuard {
	t.Helper()
	f := &fakeAdGuard{rules: append([]string{}, initial...)}

	mux := http.NewServeMux()
	mux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u == "" || p == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failGets > 0 {
			f.failGets--
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if f.status != "" {
			_, _ = w.Write([]byte(f.status))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": true, "user_rules": append([]string{}, f.rules...)})
	})
	mux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Rules []string `json:"rules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failSets > 0 {
			f.failSets--
			if f.applyThen {
				f.rules = body.Rules
			}
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		f.rules = body.Rules
		f.writes++
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// inject changes the failure settings under the lock.
func (f *fakeAdGuard) inject(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *fakeAdGuard) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

func (f *fakeAdGuard) current() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.rules...)
}

func TestSinkholeApplyAndRevert(t *testing.T) {
	ag := newFakeAdGuard(t, "||operator-rule.example^")
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)
	action := &events.EnforcementAction{ID: "ACT-1", BlockedDomain: "evil.example"}

	if err := d.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rules := ag.current()
	if len(rules) != 2 || rules[1] != "||evil.example^" {
		t.Fatalf("rule not appended: %v", rules)
	}
	// The operator's own rule must survive a read-modify-write cycle.
	if rules[0] != "||operator-rule.example^" {
		t.Errorf("operator rule was lost: %v", rules)
	}

	if err := d.Revert(context.Background(), action); err != nil {
		t.Fatalf("revert: %v", err)
	}
	rules = ag.current()
	if len(rules) != 1 || rules[0] != "||operator-rule.example^" {
		t.Fatalf("revert should leave only the operator rule: %v", rules)
	}
}

func TestSinkholeApplyIsIdempotent(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)
	action := &events.EnforcementAction{ID: "ACT-1", BlockedDomain: "evil.example"}

	for i := 0; i < 3; i++ {
		if err := d.Apply(context.Background(), action); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	if rules := ag.current(); len(rules) != 1 {
		t.Fatalf("repeated apply should not duplicate the rule: %v", rules)
	}
}

// TestSinkholeRejectsRuleInjection is the regression test for the injection
// path: AdGuard stores user_rules as newline-separated text, so a domain
// containing a newline would append EXTRA filter rules. "||*^" blocks every
// domain, which would take DNS down for the whole household.
func TestSinkholeRejectsRuleInjection(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)

	for _, domain := range []string{
		"evil.example^\n||*^",
		"evil.example\n||*^",
		"evil.example^\r\n||*^",
		"*",
		"||*^",
		"evil example",
		"-leading-hyphen.example",
		"",
		"   ",
		".",
		"no-dot",
		strings.Repeat("a", 300) + ".example",
	} {
		action := &events.EnforcementAction{ID: "ACT-x", BlockedDomain: domain}
		if err := d.Apply(context.Background(), action); err == nil {
			t.Errorf("domain %q should have been refused", domain)
		}
	}
	if rules := ag.current(); len(rules) != 0 {
		t.Fatalf("no rule should have been written: %v", rules)
	}
}

func TestSinkholeNormalizesDomain(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)
	action := &events.EnforcementAction{ID: "ACT-1", BlockedDomain: "  EVIL.Example.  "}

	if err := d.Apply(context.Background(), action); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rules := ag.current(); len(rules) != 1 || rules[0] != "||evil.example^" {
		t.Fatalf("domain should be normalized to lowercase without trailing dot: %v", rules)
	}
}

// TestSinkholeConcurrentApplyKeepsEveryRule covers the lost-update bug: the
// driver is called concurrently from /evaluate, /approve, /revert and the TTL
// goroutine, and each call rewrites the WHOLE rule list.
func TestSinkholeConcurrentApplyKeepsEveryRule(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)

	domains := []string{
		"a.example", "b.example", "c.example", "d.example", "e.example",
		"f.example", "g.example", "h.example", "i.example", "j.example",
	}

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			action := &events.EnforcementAction{ID: "ACT-" + dom, BlockedDomain: dom}
			if err := d.Apply(context.Background(), action); err != nil {
				t.Errorf("apply %s: %v", dom, err)
			}
		}(domain)
	}
	wg.Wait()

	rules := ag.current()
	if len(rules) != len(domains) {
		t.Fatalf("expected %d rules after concurrent applies, got %d: %v",
			len(domains), len(rules), rules)
	}
	for _, dom := range domains {
		want := "||" + dom + "^"
		found := false
		for _, r := range rules {
			if r == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("rule for %s was lost to a concurrent write", dom)
		}
	}
}

func TestSinkholeReportsUpstreamFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(srv.Close)

	d := NewSinkholeDriver(srv.URL, "admin", "pw", nil)
	action := &events.EnforcementAction{ID: "ACT-1", BlockedDomain: "evil.example"}
	if err := d.Apply(context.Background(), action); err == nil {
		t.Fatal("a 500 from AdGuard must fail Apply, not be swallowed")
	}
}

func TestValidateDomain(t *testing.T) {
	ok := []string{
		"example.com", "a.b.c.example.com", "xn--80ak6aa92e.com", "1-2.example",
		"123.example", "evil.example.co.uk", "someone.github.io", "c2.evil.test",
	}
	for _, d := range ok {
		if _, err := validateDomain(d); err != nil {
			t.Errorf("validateDomain(%q) should pass: %v", d, err)
		}
	}
	bad := []string{"", ".", "no-dot", "-bad.example", "bad-.example", "a..b", "with space.example"}
	for _, d := range bad {
		if _, err := validateDomain(d); err == nil {
			t.Errorf("validateDomain(%q) should fail", d)
		}
	}
}

// TestValidateDomainRefusesAddresses: "203.0.113.9" is a valid hostname by
// grammar alone, so an IP from Zeek Intel was accepted as ||203.0.113.9^.
func TestValidateDomainRefusesAddresses(t *testing.T) {
	for _, d := range []string{
		"203.0.113.9", "1.2.3.4", "192.168.001.001", "10.0.0.1.", "1.2.3.4.5", "255.255.255.255",
	} {
		if got, err := validateDomain(d); err == nil {
			t.Errorf("validateDomain(%q) = %q, an address must never become a filter rule", d, got)
		} else if !strings.Contains(err.Error(), "IP address") {
			t.Errorf("validateDomain(%q): error should say why, got %v", d, err)
		}
	}
}

// TestValidateDomainRefusesPublicSuffixes: ||co.uk^ blocks every UK
// registrant; ||github.io^ every GitHub Pages site.
func TestValidateDomainRefusesPublicSuffixes(t *testing.T) {
	for _, d := range []string{"co.uk", "CO.UK.", "com.au", "github.io", "s3.amazonaws.com", "blogspot.com"} {
		if got, err := validateDomain(d); err == nil {
			t.Errorf("validateDomain(%q) = %q, a public suffix must never become a filter rule", d, got)
		} else if !strings.Contains(err.Error(), "public suffix") {
			t.Errorf("validateDomain(%q): error should say why, got %v", d, err)
		}
	}
}

// TestSinkholeRefusesWhatThe1xEngineSent runs the values the 1.x
// detection-engine actually put in `domain` through the driver. None of them
// names a domain, and none may reach AdGuard.
func TestSinkholeRefusesWhatThe1xEngineSent(t *testing.T) {
	ag := newFakeAdGuard(t)
	d := NewSinkholeDriver(ag.srv.URL, "admin", "pw", nil)
	for _, domain := range []string{
		"cdn.legit.example (→203.0.113.7)",         // DNS-answer IP-IoC hit
		"ET MALWARE Cobalt Strike Beacon Observed", // Suricata alert
		"192.168.1.50",                         // volumetric anomaly: the device's own address
		"198.51.100.20",                        // address-only beacon / DNS-less TLS / Zeek ADDR hit
		"t13d3012h2_1d37bd780c83_882d495ac381", // Zeek TLSFP intel hit
	} {
		action := &events.EnforcementAction{ID: "ACT-x", BlockedDomain: domain}
		if err := d.Apply(context.Background(), action); err == nil {
			t.Errorf("%q must be refused", domain)
		}
	}
	if rules := ag.current(); len(rules) != 0 {
		t.Fatalf("no rule should have been written: %v", rules)
	}
}
