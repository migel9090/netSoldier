package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// metricValue reads one counter or gauge series from the default registry.
func metricValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if v, ok := labels[l.GetName()]; ok && v != l.GetValue() {
					continue series
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			return m.GetGauge().GetValue()
		}
	}
	return 0
}

// roleEnv is the production routing behind the production middleware.
type roleEnv struct {
	*harness
	drv *recordingDriver
}

func newRoleEnv(t *testing.T) *roleEnv {
	t.Helper()
	drv := &recordingDriver{}
	return &roleEnv{harness: newHarness(t, harnessOpts{driver: drv}), drv: drv}
}

func (e *roleEnv) do(t *testing.T, method, path, token string, body []byte, sign bool) int {
	t.Helper()
	hdr := map[string]string{actorHeader: testActor}
	if sign {
		hdr[events.SignatureHeader] = events.SignPayload(testWebhookSecret, body)
	}
	status, _ := e.request(method, path, token, body, hdr)
	return status
}

// TestIngestTokenCannotOperate: one key used to do both jobs, so the
// detection-engine — the component that parses untrusted network data —
// could approve, reject or revert the actions it had itself submitted.
func TestIngestTokenCannotOperate(t *testing.T) {
	env := newRoleEnv(t)
	a := env.createPending("02:00:00:00:00:01", "192.168.1.50", "evil.example")

	wrongRole := map[string]string{"reason": "wrong_role"}
	for _, ep := range []struct{ method, path string }{
		{http.MethodPost, "/actions/" + a.ID + "/approve"},
		{http.MethodPost, "/actions/" + a.ID + "/reject"},
		{http.MethodPost, "/actions/" + a.ID + "/revert"},
		{http.MethodGet, "/actions/pending"},
		{http.MethodGet, "/actions/" + a.ID},
		{http.MethodGet, "/allowlist"},
		{http.MethodGet, "/policy"},
		{http.MethodGet, "/audit"},
		{http.MethodPost, "/agent/v1/poll"},
	} {
		before := metricValue(t, "killswitch_rejected_requests_total", wrongRole)
		if got := env.do(t, ep.method, ep.path, testIngestToken, []byte(`{}`), false); got != http.StatusUnauthorized {
			t.Errorf("%s %s with the ingest token: %d, want 401", ep.method, ep.path, got)
		}
		if metricValue(t, "killswitch_rejected_requests_total", wrongRole) != before+1 {
			t.Errorf("%s %s: refusal not counted as wrong_role", ep.method, ep.path)
		}
	}
	if got := env.action(a.ID).State; got != events.StatePending || env.drv.applied.Load() != 0 {
		t.Fatalf("the ingest token changed an action: state %q, %d applies", got, env.drv.applied.Load())
	}

	if got := env.do(t, http.MethodPost, "/actions/"+a.ID+"/approve", testOperatorToken, []byte(`{}`), false); got != http.StatusOK {
		t.Fatalf("the operator token must still approve, got %d", got)
	}
}

// TestOperatorTokenCannotSubmitEvents: the operator credential is held by
// the web UI; it has no business creating detections.
func TestOperatorTokenCannotSubmitEvents(t *testing.T) {
	env := newRoleEnv(t)
	body, _ := json.Marshal(criticalIoCEvent())
	before := metricValue(t, "killswitch_rejected_requests_total", map[string]string{"reason": "wrong_role"})
	if got := env.do(t, http.MethodPost, "/evaluate", testOperatorToken, body, true); got != http.StatusUnauthorized {
		t.Fatalf("operator token on /evaluate: %d, want 401", got)
	}
	if metricValue(t, "killswitch_rejected_requests_total", map[string]string{"reason": "wrong_role"}) != before+1 {
		t.Error("refusal not counted as wrong_role")
	}
	if got := env.do(t, http.MethodPost, "/evaluate", testIngestToken, body, true); got != http.StatusOK {
		t.Fatalf("ingest token + signature on /evaluate: %d, want 200", got)
	}
	if got := env.do(t, http.MethodPost, "/evaluate", testIngestToken, body, false); got != http.StatusUnauthorized {
		t.Fatalf("the ingest token alone, without the signature, must not do: %d", got)
	}
}

// TestPathSpellingsCannotSkipEvaluateChecks is the auditor's probe: the
// signature check keyed on the literal path, so the question is whether any
// spelling reaches the evaluate handler without the ingest checks.
func TestPathSpellingsCannotSkipEvaluateChecks(t *testing.T) {
	env := newRoleEnv(t)
	body, _ := json.Marshal(criticalIoCEvent())
	for _, p := range []string{"/evaluate", "//evaluate", "/evaluate/", "/./evaluate", "/%65valuate",
		"/EVALUATE", "/x/../evaluate", "/evaluate?x=1", "/evaluate%2f", "/evaluate;x"} {
		for _, token := range []string{testOperatorToken, testIngestToken} {
			// valid bearer of either role, NO signature
			env.do(t, http.MethodPost, p, token, body, false)
		}
	}
	if n := env.actionCount(); n != 0 {
		t.Fatalf("%d actions created without a signature", n)
	}
	if env.drv.applied.Load() != 0 {
		t.Fatal("a driver ran for an unsigned event")
	}
}

func TestUnknownRouteNeedsOperatorToken(t *testing.T) {
	env := newRoleEnv(t)
	if got := env.do(t, http.MethodGet, "/nope", "", nil, false); got != http.StatusUnauthorized {
		t.Errorf("unknown route without a token: %d, want 401", got)
	}
	if got := env.do(t, http.MethodGet, "/nope", testOperatorToken, nil, false); got != http.StatusNotFound {
		t.Errorf("unknown route with the operator token: %d, want 404", got)
	}
}

// TestLoadAuthRefusesIncompleteCredentials: an empty KILLSWITCH_API_KEY
// used to switch authentication off with a log line.
func TestLoadAuthRefusesIncompleteCredentials(t *testing.T) {
	full := map[string]string{
		"KILLSWITCH_API_KEY":      "op",
		"KILLSWITCH_INGEST_TOKEN": "in",
		"WEBHOOK_SECRET":          "s",
	}
	cases := []struct {
		name  string
		unset string
		set   map[string]string
		want  string
	}{
		{name: "no operator token", unset: "KILLSWITCH_API_KEY", want: "KILLSWITCH_API_KEY (operator token) is not set"},
		{name: "no ingest token", unset: "KILLSWITCH_INGEST_TOKEN", want: "KILLSWITCH_INGEST_TOKEN (ingest token) is not set"},
		{name: "no webhook secret", unset: "WEBHOOK_SECRET", want: "WEBHOOK_SECRET is not set"},
		{name: "one key for both roles", set: map[string]string{"KILLSWITCH_INGEST_TOKEN": "op"}, want: "are the same value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range full {
				t.Setenv(k, v)
			}
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			if tc.unset != "" {
				t.Setenv(tc.unset, "")
			}
			_, _, err := loadAuth(time.Minute)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), insecureEnv) {
				t.Fatalf("got %v, want a refusal saying %q and naming %s", err, tc.want, insecureEnv)
			}

			t.Setenv(insecureEnv, "true")
			if _, _, err := loadAuth(time.Minute); err != nil {
				t.Fatalf("with %s=true the service may start: %v", insecureEnv, err)
			}
		})
	}

	for k, v := range full {
		t.Setenv(k, v)
	}
	t.Setenv(insecureEnv, "")
	creds, verifier, err := loadAuth(2 * time.Minute)
	if err != nil || creds.operator != "op" || creds.ingest != "in" || verifier == nil || verifier.Tolerance != 2*time.Minute {
		t.Fatalf("complete configuration: %+v %+v %v", creds, verifier, err)
	}
}
