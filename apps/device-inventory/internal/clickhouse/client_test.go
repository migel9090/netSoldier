package clickhouse

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type recorded struct {
	user, key, query, database, body string
	params                           map[string]string
}

func fakeServer(t *testing.T, status int, reply string) (*httptest.Server, *[]recorded) {
	t.Helper()
	var calls []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		rec := recorded{
			user: r.Header.Get("X-ClickHouse-User"), key: r.Header.Get("X-ClickHouse-Key"),
			query: r.URL.Query().Get("query"), database: r.URL.Query().Get("database"),
			body: string(b), params: map[string]string{},
		}
		for k, v := range r.URL.Query() {
			if strings.HasPrefix(k, "param_") {
				rec.params[strings.TrimPrefix(k, "param_")] = v[0]
			}
		}
		calls = append(calls, rec)
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestUInt64AcceptsQuotedAndBare(t *testing.T) {
	var v struct {
		A UInt64 `json:"a"`
		B UInt64 `json:"b"`
		C UInt64 `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":"18446744073709551615","b":42,"c":null}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A != 18446744073709551615 || v.B != 42 || v.C != 0 {
		t.Errorf("got %+v", v)
	}
	for _, bad := range []string{`"-1"`, `"x"`, `1.5`, `"`} {
		var u UInt64
		if err := json.Unmarshal([]byte(bad), &u); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if b, _ := json.Marshal(struct{ N UInt64 }{7}); string(b) != `{"N":7}` {
		t.Errorf("marshals as %s, want a number", b)
	}
}

// DI-5: InitSchema sent no credentials; every call must.
func TestEveryCallSendsCredentials(t *testing.T) {
	srv, calls := fakeServer(t, 200, `{"data":[{"name":"devices"},{"name":"device_events"}]}`)
	c := NewClient(srv.URL, "netsoldier", "writer", "s3cret")
	ctx := context.Background()

	if err := c.Insert(ctx, "device_events", DeviceEvent{Timestamp: "2026-11-16 12:00:00.123", MAC: "aa:bb:cc:dd:ee:ff", EventType: "seen"}); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckSchema(ctx, "devices", "device_events"); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := c.Query(ctx, "SELECT 1 WHERE x = {ip:String}", &rows, map[string]string{"ip": "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 3 {
		t.Fatalf("%d calls", len(*calls))
	}
	for i, r := range *calls {
		if r.user != "writer" || r.key != "s3cret" || r.database != "netsoldier" {
			t.Errorf("call %d: user=%q key=%q db=%q", i, r.user, r.key, r.database)
		}
		if strings.Contains(r.query, "s3cret") {
			t.Errorf("call %d leaks the password into the URL", i)
		}
	}
	ins := (*calls)[0]
	if ins.query != "INSERT INTO device_events FORMAT JSONEachRow" ||
		!strings.Contains(ins.body, `"timestamp":"2026-11-16 12:00:00.123"`) || !strings.HasSuffix(ins.body, "\n") {
		t.Errorf("insert: %q %q", ins.query, ins.body)
	}
	if q := (*calls)[2]; !strings.HasSuffix(q.query, " FORMAT JSON") || q.params["ip"] != "1.2.3.4" {
		t.Errorf("query: %q %v", q.query, q.params)
	}
}

func TestEmptyUserIsSentAsDefault(t *testing.T) {
	srv, calls := fakeServer(t, 200, "")
	if err := NewClient(srv.URL, "netsoldier", "", "").Insert(context.Background(), "t", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if (*calls)[0].user != "default" {
		t.Errorf("user %q", (*calls)[0].user)
	}
}

func TestErrorsCarryTheServerMessage(t *testing.T) {
	srv, _ := fakeServer(t, 516, "Code: 516. DB::Exception: writer: Authentication failed\n")
	c := NewClient(srv.URL, "netsoldier", "writer", "wrong")
	err := c.Insert(context.Background(), "device_events", map[string]int{"a": 1})
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Errorf("insert error: %v", err)
	}
	var rows []any
	if err := c.Query(context.Background(), "SELECT 1", &rows); err == nil {
		t.Error("query error swallowed")
	}
	if err := c.Insert(context.Background(), "t"); err != nil {
		t.Errorf("an empty insert is a no-op: %v", err)
	}
}

func TestCheckSchemaReportsMissingTables(t *testing.T) {
	srv, _ := fakeServer(t, 200, `{"data":[{"name":"device_events"}]}`)
	err := NewClient(srv.URL, "netsoldier", "writer", "pw").CheckSchema(context.Background(), "devices", "device_events")
	if err == nil || !strings.Contains(err.Error(), "netsoldier.devices") {
		t.Errorf("err = %v", err)
	}
	srv2, _ := fakeServer(t, 200, `not json`)
	if err := NewClient(srv2.URL, "netsoldier", "writer", "pw").CheckSchema(context.Background(), "devices"); err == nil {
		t.Error("garbage response accepted")
	}
	srv3, _ := fakeServer(t, 200, `{"meta":[]}`)
	var rows []any
	if err := NewClient(srv3.URL, "netsoldier", "writer", "pw").Query(context.Background(), "SELECT 1", &rows); err == nil {
		t.Error("response without data accepted")
	}
}
