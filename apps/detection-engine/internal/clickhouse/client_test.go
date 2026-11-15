package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type seen struct {
	user, key, auth string
	query           string
	params          map[string]string
	body            string
}

// fakeCH answers like ClickHouse: 516 when the credentials are not the
// expected ones, rows otherwise.
func fakeCH(t *testing.T, user, password, rows string) (*httptest.Server, func() []seen) {
	var mu sync.Mutex
	var reqs []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := seen{
			user: r.Header.Get(HeaderUser), key: r.Header.Get(HeaderKey), auth: r.Header.Get("Authorization"),
			query: r.URL.Query().Get("query"), params: map[string]string{}, body: string(body),
		}
		for k := range r.URL.Query() {
			s.params[k] = r.URL.Query().Get(k)
		}
		mu.Lock()
		reqs = append(reqs, s)
		mu.Unlock()
		if s.user != user || s.key != password {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, "Code: 516. DB::Exception: %s: Authentication failed", firstNonEmpty(s.user, "default"))
			return
		}
		fmt.Fprint(w, rows)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []seen {
		mu.Lock()
		defer mu.Unlock()
		return append([]seen(nil), reqs...)
	}
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestCredentialsFromEnvTravelInHeaders: the manifests set CLICKHOUSE_USER
// and CLICKHOUSE_PASSWORD but nothing read them, so every sensor poll and
// every feedback write ran as `default` and was refused.
func TestCredentialsFromEnvTravelInHeaders(t *testing.T) {
	srv, reqs := fakeCH(t, "writer", "s3cret", `{"n":1}`+"\n"+`{"n":2}`+"\n")
	cfg, ok := ConfigFromEnv(envMap(map[string]string{
		"CLICKHOUSE_URL": srv.URL, "CLICKHOUSE_USER": "writer", "CLICKHOUSE_PASSWORD": "s3cret",
	}))
	if !ok || cfg.Database != "netsoldier" {
		t.Fatalf("ConfigFromEnv = %+v, %v", cfg, ok)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Authenticated() {
		t.Error("a configured user must count as authenticated")
	}

	var rows []json.RawMessage
	if err := c.QueryJSONEachRow(context.Background(), "SELECT 1 FORMAT JSONEachRow", func(r json.RawMessage) error {
		rows = append(rows, r)
		return nil
	}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("rows = %d, want 2", len(rows))
	}
	if err := c.Insert(context.Background(), "detection_feedback", map[string]any{"a": 1}, map[string]any{"a": 2}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	for _, r := range reqs() {
		if r.user != "writer" || r.key != "s3cret" {
			t.Errorf("request sent user=%q key=%q, want the configured credentials", r.user, r.key)
		}
		if r.params["database"] != "netsoldier" {
			t.Errorf("database = %q", r.params["database"])
		}
		for k := range r.params {
			if k == "user" || k == "password" {
				t.Errorf("credentials leaked into the URL (%s)", k)
			}
		}
	}
	ins := reqs()[1]
	if ins.query != "INSERT INTO detection_feedback FORMAT JSONEachRow" || ins.body != "{\"a\":1}\n{\"a\":2}\n" {
		t.Errorf("insert sent query=%q body=%q", ins.query, ins.body)
	}
	if ins.params["input_format_skip_unknown_fields"] != "0" {
		t.Error("an insert must fail on a column the table lacks, not drop the field silently")
	}
}

// TestCredentialsInURLMoveToHeaders: ClickHouse refuses a request that
// authenticates twice, and a URL with a password ends up in logs.
func TestCredentialsInURLMoveToHeaders(t *testing.T) {
	srv, reqs := fakeCH(t, "ml", "pw", "")
	u := strings.Replace(srv.URL, "http://", "http://ml:pw@", 1)
	c, err := New(Config{URL: u, Database: "netsoldier"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.String(), "pw") {
		t.Errorf("String() = %q leaks the password", c.String())
	}
	if err := c.Insert(context.Background(), "t", map[string]int{"x": 1}); err != nil {
		t.Fatal(err)
	}
	r := reqs()[0]
	if r.user != "ml" || r.key != "pw" || r.auth != "" {
		t.Errorf("user=%q key=%q Authorization=%q; want header credentials only", r.user, r.key, r.auth)
	}
}

// TestFailedWriteIsCounted: write failures were Debug lines next to
// counters that kept rising.
func TestFailedWriteIsCounted(t *testing.T) {
	srv, _ := fakeCH(t, "writer", "right", "")
	c, _ := New(Config{URL: srv.URL, Database: "netsoldier", User: "writer", Password: "wrong"})
	before := testutil.ToFloat64(writeFailures.WithLabelValues("detection_feedback"))
	err := c.Insert(context.Background(), "detection_feedback", map[string]int{"x": 1}, map[string]int{"x": 2})
	if err == nil || !strings.Contains(err.Error(), "516") {
		t.Fatalf("Insert error = %v, want ClickHouse's refusal", err)
	}
	if got := testutil.ToFloat64(writeFailures.WithLabelValues("detection_feedback")) - before; got != 2 {
		t.Errorf("write failures counted %v, want 2 rows", got)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Errorf("error %q contains the password", err)
	}

	if err := c.QueryJSONEachRow(context.Background(), "SELECT 1", func(json.RawMessage) error { return nil }); err == nil {
		t.Error("a refused query must be an error")
	}
}

func TestInvalidInput(t *testing.T) {
	if _, err := New(Config{URL: "clickhouse:8123"}); err == nil {
		t.Error("a URL without scheme accepted")
	}
	if _, err := New(Config{URL: "http://u:pw@[::"}); err == nil || strings.Contains(err.Error(), "pw") {
		t.Errorf("an unparsable URL must be refused without echoing its password: %v", err)
	}
	if _, ok := ConfigFromEnv(envMap(nil)); ok {
		t.Error("no CLICKHOUSE_URL must mean no ClickHouse")
	}
	srv, reqs := fakeCH(t, "", "", "")
	c, _ := New(Config{URL: srv.URL + "/", Database: "netsoldier"})
	if c.Authenticated() {
		t.Error("no user configured, yet Authenticated")
	}
	if err := c.Insert(context.Background(), "x; DROP TABLE y", 1); err == nil {
		t.Error("an invalid table name was sent")
	}
	if len(reqs()) != 0 {
		t.Error("a request was made for an invalid table name")
	}
	if err := c.Insert(context.Background(), "t", func() {}); err == nil {
		t.Error("an unencodable row was accepted")
	}

	srv.Close()
	if err := c.Insert(context.Background(), "t", 1); err == nil {
		t.Error("unreachable server: no error")
	}
}

func TestQueryCallbackErrorStops(t *testing.T) {
	srv, _ := fakeCH(t, "", "", "{}\n\n{}\n")
	c, _ := New(Config{URL: srv.URL, Database: "d"})
	n := 0
	err := c.QueryJSONEachRow(context.Background(), "q", func(json.RawMessage) error {
		n++
		return fmt.Errorf("stop")
	})
	if err == nil || n != 1 {
		t.Errorf("err=%v after %d rows; want the callback's error after the first", err, n)
	}
}
