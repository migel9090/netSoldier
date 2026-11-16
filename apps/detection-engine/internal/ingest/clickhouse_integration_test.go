package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
)

// These run the pollers against a real ClickHouse with the repository's
// schema. Skipped unless configured, so `go test ./...` stays hermetic:
//
//	DETECTION_ENGINE_TEST_CLICKHOUSE_URL       e.g. http://172.17.0.5:8123
//	DETECTION_ENGINE_TEST_CLICKHOUSE_USER      a user that may INSERT and SELECT
//	DETECTION_ENGINE_TEST_CLICKHOUSE_PASSWORD  on the netsoldier sensor tables
//	DETECTION_ENGINE_TEST_CLICKHOUSE_MIGRATE   1: apply deploy/clickhouse/migrations
//	                                           first if the schema is not there
//
// Use the deployed image (clickhouse/clickhouse-server:24.3-alpine) with the
// `tiered` storage policy mounted (see tests/e2e/clickhouse_cold_test.go):
// migrations 018 and later need it. Every run writes rows of its own and
// counts only those, so a server can be reused.

type liveCH struct {
	base, user, password string
	client               *clickhouse.Client
}

func connectLive(t *testing.T) *liveCH {
	t.Helper()
	base := os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_URL")
	if base == "" {
		t.Skip("DETECTION_ENGINE_TEST_CLICKHOUSE_URL not set")
	}
	l := &liveCH{base: strings.TrimRight(base, "/"),
		user: os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_USER"), password: os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_PASSWORD")}
	c, err := clickhouse.New(clickhouse.Config{URL: base, Database: "netsoldier", User: l.user, Password: l.password})
	if err != nil {
		t.Fatal(err)
	}
	l.client = c
	if l.query(t, "SELECT count() FROM system.columns WHERE database = 'netsoldier' AND table = 'suricata_alerts' AND name = 'ingested_at'") != "1" {
		if os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_MIGRATE") != "1" {
			t.Fatal("netsoldier.suricata_alerts has no ingested_at: apply the migrations, or set DETECTION_ENGINE_TEST_CLICKHOUSE_MIGRATE=1")
		}
		l.migrate(t)
	}
	return l
}

func (l *liveCH) do(t *testing.T, q url.Values, body string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, l.base+"/?"+q.Encode(), strings.NewReader(body))
	if l.user != "" {
		req.Header.Set(clickhouse.HeaderUser, l.user)
		req.Header.Set(clickhouse.HeaderKey, l.password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clickhouse %d: %s", resp.StatusCode, b)
	}
	return strings.TrimSpace(string(b))
}

func (l *liveCH) query(t *testing.T, sql string) string {
	t.Helper()
	return l.do(t, url.Values{}, sql)
}

func (l *liveCH) insert(t *testing.T, table string, rows ...map[string]any) {
	t.Helper()
	var b strings.Builder
	for _, r := range rows {
		j, _ := json.Marshal(r)
		b.Write(j)
		b.WriteByte('\n')
	}
	l.do(t, url.Values{"database": {"netsoldier"}, "query": {"INSERT INTO " + table + " FORMAT JSONEachRow"}}, b.String())
}

// migrate applies the repository's migration files in order, statement by
// statement, the way tests/e2e does.
func (l *liveCH) migrate(t *testing.T) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "deploy", "clickhouse", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		var kept []string
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "--") {
				kept = append(kept, line)
			}
		}
		for _, stmt := range strings.Split(strings.Join(kept, "\n"), ";") {
			if stmt = strings.TrimSpace(stmt); stmt != "" {
				l.query(t, stmt)
			}
		}
		t.Logf("applied %s", f)
	}
}

func (l *liveCH) poller(src Source, cursors *store.Cursors, got *[]SensorEvent) *Poller {
	return NewPoller(l.client, src, time.Hour, func(ev SensorEvent) { *got = append(*got, ev) },
		PollerOptions{Cursors: cursors})
}

func countIndicator(evs []SensorEvent, ind string) int {
	n := 0
	for _, ev := range evs {
		if ev.Indicator == ind {
			n++
		}
	}
	return n
}

func liveIntel(eventTime time.Time, uid, indicator string) map[string]any {
	return map[string]any{"timestamp": eventTime.Unix(), "uid": uid, "src_ip": "192.168.1.66", "src_port": 1,
		"dst_ip": "192.168.1.2", "dst_port": 53, "indicator": indicator, "indicator_type": "Intel::DOMAIN",
		"seen_where": "DNS::IN_REQUEST", "matched": []string{"Intel::DOMAIN"}, "sources": []string{"threatfox"}}
}

func memCursors(t *testing.T) *store.Cursors {
	t.Helper()
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st.Cursors()
}

// TestLiveBurstInOneSecondDoesNotStallSource: 1200 rows in one INSERT, all
// in one event second, then a real hit. The old poller returned the same
// 1000 rows forever and never saw the hit.
func TestLiveBurstInOneSecondDoesNotStallSource(t *testing.T) {
	l := connectLive(t)
	ctx := context.Background()
	run := time.Now().UnixNano()
	noise := fmt.Sprintf("noise-%d.listed.example", run)
	real := fmt.Sprintf("c2-%d.real-threat.example", run)

	var got []SensorEvent
	p := l.poller(ZeekIntel{}, memCursors(t), &got)
	if err := p.poll(ctx); err != nil { // position: now
		t.Fatal(err)
	}
	burst := time.Now().Truncate(time.Second)
	rows := make([]map[string]any, 1200)
	for i := range rows {
		rows[i] = liveIntel(burst, fmt.Sprintf("F%d-%d", run, i), noise)
	}
	l.insert(t, "zeek_intel", rows...)
	same := l.query(t, fmt.Sprintf("SELECT uniqExact(ingested_at) FROM netsoldier.zeek_intel WHERE indicator = '%s'", noise))
	l.insert(t, "zeek_intel", liveIntel(burst.Add(2*time.Minute), "REAL", real))

	for i := 0; i < 3; i++ {
		if err := p.poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("1200 rows inserted together carried %s distinct ingested_at value(s); emitted noise=%d real=%d",
		same, countIndicator(got, noise), countIndicator(got, real))
	if n := countIndicator(got, noise); n != 1200 {
		t.Errorf("burst rows emitted %d times, want each once (1200)", n)
	}
	if n := countIndicator(got, real); n != 1 {
		t.Errorf("the hit after the burst was emitted %d times, want 1: the source stalled", n)
	}
}

// TestLiveLateRowWithOlderEventTimeIsRead: a row whose event time is an hour
// older than rows already read, arriving after them.
func TestLiveLateRowWithOlderEventTimeIsRead(t *testing.T) {
	l := connectLive(t)
	ctx := context.Background()
	run := time.Now().UnixNano()
	fast := fmt.Sprintf("fast-%d.example", run)
	late := fmt.Sprintf("late-%d.real-threat.example", run)

	var got []SensorEvent
	p := l.poller(ZeekIntel{}, memCursors(t), &got)
	l.insert(t, "zeek_intel", liveIntel(time.Now(), "A", fast))
	if err := p.poll(ctx); err != nil {
		t.Fatal(err)
	}
	l.insert(t, "zeek_intel", liveIntel(time.Now().Add(-time.Hour), "B", late))
	if err := p.poll(ctx); err != nil {
		t.Fatal(err)
	}
	if countIndicator(got, fast) != 1 || countIndicator(got, late) != 1 {
		t.Errorf("fast=%d late=%d, want both once", countIndicator(got, fast), countIndicator(got, late))
	}
}

// TestLiveHitWrittenWhileDownIsDetectedAfterStart: the position is stored;
// what lands while no engine runs is read by the next one.
func TestLiveHitWrittenWhileDownIsDetectedAfterStart(t *testing.T) {
	l := connectLive(t)
	ctx := context.Background()
	run := time.Now().UnixNano()
	down := fmt.Sprintf("down-%d.real-threat.example", run)
	path := filepath.Join(t.TempDir(), "de.db")

	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []SensorEvent
	if err := l.poller(ZeekIntel{}, st.Cursors(), &got).poll(ctx); err != nil {
		t.Fatal(err)
	}
	st.Close() // the engine stops

	l.insert(t, "zeek_intel", liveIntel(time.Now().Add(-10*time.Minute), "DOWN", down))
	time.Sleep(1100 * time.Millisecond)

	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got = nil
	if err := l.poller(ZeekIntel{}, st.Cursors(), &got).poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countIndicator(got, down); n != 1 {
		t.Fatalf("hit written while down emitted %d times after start, want 1", n)
	}
}

// TestLiveEverySourceQueryRuns: each source's real query parses on the
// server and its rows come back through the parser.
func TestLiveEverySourceQueryRuns(t *testing.T) {
	l := connectLive(t)
	ctx := context.Background()
	run := time.Now().UnixNano()
	now := time.Now().Unix()
	tag := fmt.Sprintf("%d", run)
	l.insert(t, "suricata_alerts", map[string]any{"timestamp": now, "flow_id": "1234567890123456789",
		"src_ip": "185.220.101.7", "src_port": 443, "dest_ip": "192.168.1.50", "dest_port": 51544, "proto": "TCP",
		"alert_signature_id": 2033000, "alert_signature": "ET MALWARE Beacon Response " + tag,
		"alert_category": "Malware Command and Control Activity Detected", "alert_severity": 1, "threat_intel": ""})
	l.insert(t, "zeek_intel", liveIntel(time.Now(), "CI"+tag, "intel-"+tag+".example"))
	l.insert(t, "zeek_ssl", map[string]any{"timestamp": now, "uid": "C" + tag, "src_ip": "192.168.1.50",
		"src_port": 1, "dst_ip": "203.0.113.7", "dst_port": 443, "server_name": "x.example", "established": 1,
		"ja3": "abc", "tls_client_fp": "t13d-" + tag})
	l.insert(t, "ml_beacons", map[string]any{"timestamp": now - 3600, "src_ip": "192.168.1.50", "dst_ip": "",
		"dst_domain": "beacon-" + tag + ".example", "beacon_score": 0.97, "connection_count": 288,
		"confidence": 73, "severity": "high", "tags": []string{"beacon"}})
	l.insert(t, "ml_anomalies", map[string]any{"timestamp": now - 600, "window_start": now - 1800,
		"src_ip": "192.168.1." + tag[len(tag)-2:], "anomaly_score": 0.91, "confidence": 66, "severity": "high",
		"conn_count": 9, "bytes_out": "18446744073709551615", "bytes_in": 1, "dst_fanout": 3, "port_fanout": 1,
		"avg_duration_ms": 1.5, "model_version": "v-" + tag, "tags": []string{"anomaly", "upload-heavy"}})

	local, _ := ParseLocalNetworks(DefaultLocalCIDRs)
	for _, src := range []Source{NewSuricataAlerts(local), ZeekIntel{}, ZeekSSL{}, MLBeacons{}, MLAnomalies{}} {
		var got []SensorEvent
		if err := l.poller(src, memCursors(t), &got).poll(ctx); err != nil {
			t.Fatalf("%s: %v", src.Name(), err)
		}
		var mine *SensorEvent
		for i := range got {
			ev := got[i]
			if strings.Contains(ev.Signature+ev.Indicator+ev.DstDomain, tag) {
				mine = &got[i]
			}
		}
		if mine == nil {
			t.Errorf("%s: this run's row did not come back (%d rows read)", src.Name(), len(got))
			continue
		}
		if mine.RowKey == "" || mine.Record() == "" {
			t.Errorf("%s: no row identity", src.Name())
		}
		t.Logf("%-16s kind=%s client=%s conf=%d sev=%s indicator=%q row=%s",
			src.Name(), mine.Kind, mine.SrcIP, mine.Confidence, mine.Severity, mine.Indicator, mine.RowKey)
		if src.Name() == "suricata_alerts" && (mine.SrcIP != "192.168.1.50" || mine.Confidence != 80) {
			t.Errorf("suricata row: client=%s conf=%d", mine.SrcIP, mine.Confidence)
		}
	}
}
