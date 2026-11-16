package drivers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func switchTarget() *events.EnforcementAction {
	return &events.EnforcementAction{ID: "ACT-r-1", TargetMAC: "02:00:00:00:00:09", TargetIP: "192.168.1.9"}
}

// closedAddr is a loopback address nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestSwitchErrorsDoNotCarryTheWebhookSecret: a webhook URL's path or
// query is often what authenticates it (an adapter's hook id, a token
// parameter). net/http puts the whole URL into a transport error, and the
// error became the action's failure_reason, an audit entry and a log line.
func TestSwitchErrorsDoNotCarryTheWebhookSecret(t *testing.T) {
	const hookID, token = "h00k-1d-5ecret", "t0ken-5ecret"
	var guard TargetGuard

	// Nothing listens: a transport error.
	addr := closedAddr(t)
	down := NewSwitchPortDriver("http://"+addr+"/api/webhook/"+hookID+"?token="+token, 0, "", &guard)
	err := down.Apply(context.Background(), switchTarget())
	if err == nil {
		t.Fatal("setup: an unreachable webhook must fail")
	}
	if msg := err.Error(); strings.Contains(msg, hookID) || strings.Contains(msg, token) || !strings.Contains(msg, addr) {
		t.Errorf("transport error %q: want the endpoint %s without the hook id or the token", msg, addr)
	}

	// The adapter answers, and its answer repeats the request.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "no route for %s (from %s)", r.URL.RequestURI(), "http://"+r.Host+r.URL.RequestURI())
	}))
	defer echo.Close()
	refusing := NewSwitchPortDriver(echo.URL+"/api/webhook/"+hookID+"?token="+token, 0, "", &guard)
	err = refusing.Apply(context.Background(), switchTarget())
	if !errors.Is(err, ErrNotApplied) {
		t.Fatalf("setup: a 404 is a refusal, got %v", err)
	}
	if msg := err.Error(); strings.Contains(msg, hookID) || strings.Contains(msg, token) || !strings.Contains(msg, "no route for") {
		t.Errorf("refusal %q: want the adapter's answer without the hook id or the token", msg)
	}
}

// TestSinkholeErrorsDoNotCarryThePassword: AdGuard's answer to a failed
// call went into the error as it came. An AdGuard, or a proxy in front of
// it, that answers with the request it got put the credential there.
func TestSinkholeErrorsDoNotCarryThePassword(t *testing.T) {
	const password = "adguard-pa55word"
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, p, _ := r.BasicAuth()
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "upstream refused: Authorization=%s password=%s", r.Header.Get("Authorization"), p)
	}))
	defer echo.Close()
	d := NewSinkholeDriver(echo.URL, "admin", password, nil)
	err := d.Apply(context.Background(), &events.EnforcementAction{ID: "ACT-r-2", BlockedDomain: "evil.example"})
	if err == nil {
		t.Fatal("setup: a 502 must fail")
	}
	basic := "YWRtaW46YWRndWFyZC1wYTU1d29yZA==" // base64("admin:adguard-pa55word")
	if msg := err.Error(); strings.Contains(msg, password) || strings.Contains(msg, basic) || !strings.Contains(msg, "upstream refused") {
		t.Errorf("error %q: want AdGuard's answer without the password or the Basic credential", msg)
	}

	// A password in ADGUARD_URL's userinfo, and AdGuard not answering.
	addr := closedAddr(t)
	d = NewSinkholeDriver("http://admin:"+password+"@"+addr, "admin", password, nil)
	err = d.Apply(context.Background(), &events.EnforcementAction{ID: "ACT-r-3", BlockedDomain: "evil.example"})
	if err == nil || strings.Contains(err.Error(), password) || !strings.Contains(err.Error(), addr) {
		t.Errorf("transport error %v: want the endpoint without the password", err)
	}
}

func TestEndpointOf(t *testing.T) {
	for raw, want := range map[string]string{
		"https://u:p@hooks.lan:8443/api/webhook/x?token=y#f": "https://hooks.lan:8443",
		"http://adguard:3000":                                "http://adguard:3000",
		"not a url":                                          "(configured URL)",
	} {
		if got := endpointOf(raw); got != want {
			t.Errorf("endpointOf(%q) = %q, want %q", raw, got, want)
		}
	}
}
