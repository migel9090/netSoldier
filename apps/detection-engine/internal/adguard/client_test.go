package adguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryLogPageParameters(t *testing.T) {
	var gotQuery, gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotUser, _, _ = r.BasicAuth()
		// "oldest" claims more than was returned; it must not be used.
		_, _ = w.Write([]byte(`{"data":[
			{"question":{"host":"b.example","type":"A"},"client":"192.168.1.5","time":"2026-11-16T12:00:02.5Z"},
			{"question":{"host":"a.example","type":"A"},"client":"192.168.1.5","time":"2026-11-16T12:00:01.25Z"}
		],"oldest":"2026-11-16T11:00:00Z"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "admin", "pw")

	before := time.Date(2026, 11, 16, 12, 0, 3, 123456789, time.FixedZone("CET", 3600))
	page, err := c.QueryLog(context.Background(), before, 2)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "limit=2&older_than=2026-11-16T11%3A00%3A03.123456789Z" || gotUser != "admin" {
		t.Errorf("query %q user %q", gotQuery, gotUser)
	}
	if len(page.Entries) != 2 || !page.Oldest.Equal(time.Date(2026, 11, 16, 12, 0, 1, 250000000, time.UTC)) {
		t.Errorf("page = %d entries, oldest %v; want the oldest entry returned", len(page.Entries), page.Oldest)
	}

	if _, err := c.QueryLog(context.Background(), time.Time{}, 5); err != nil || gotQuery != "limit=5" {
		t.Errorf("first page: query %q err %v", gotQuery, err)
	}
}

// TestQueryLogRealAdGuardEntry decodes an entry exactly as AdGuard Home
// v0.107.55 returns it (captured on the lite lab host). The question is
// "name", not "host": reading only "host" left every queried name empty and
// no DNS detection could match.
func TestQueryLogRealAdGuardEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"answer":[{"type":"A","value":"172.66.147.243","ttl":230},
			{"type":"A","value":"104.20.23.154","ttl":230}],"answer_dnssec":true,"cached":false,
			"client":"192.168.77.114","client_info":{"whois":{},"name":"","disallowed_rule":"192.168.77.114",
			"disallowed":false},"client_proto":"","elapsedMs":"24.480895999999998",
			"question":{"class":"IN","name":"example.com","type":"A"},"reason":"NotFilteredNotFound",
			"rules":[],"status":"NOERROR","time":"2026-11-16T15:45:11.366933906Z",
			"upstream":"https://dns.cloudflare.com:443/dns-query"}],"oldest":"2026-11-16T15:45:11.366933906Z"}`))
	}))
	defer srv.Close()

	page, err := NewClient(srv.URL, "u", "p").QueryLog(context.Background(), time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 {
		t.Fatalf("got %d entries", len(page.Entries))
	}
	e := page.Entries[0]
	if e.Question.Host != "example.com" || e.Question.Type != "A" || e.Client != "192.168.77.114" {
		t.Errorf("question %+v client %q: the queried name was not read", e.Question, e.Client)
	}
	if len(e.Answer) != 2 || e.Answer[0].Value != "172.66.147.243" || e.Answer[0].TTL != 230 {
		t.Errorf("answers %+v", e.Answer)
	}
}

func TestQueryLogErrors(t *testing.T) {
	status := http.StatusUnauthorized
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "u", "p")
	if _, err := c.QueryLog(context.Background(), time.Time{}, 1); err == nil {
		t.Error("a 401 must be an error")
	}
	status = http.StatusOK
	if _, err := c.QueryLog(context.Background(), time.Time{}, 1); err == nil {
		t.Error("an undecodable body must be an error")
	}
	srv.Close()
	if _, err := c.QueryLog(context.Background(), time.Time{}, 1); err == nil {
		t.Error("an unreachable server must be an error")
	}
	if _, err := NewClient("http://[::1", "u", "p").QueryLog(context.Background(), time.Time{}, 1); err == nil {
		t.Error("a malformed URL must be an error")
	}
}
