//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// ── Legacy server ────────────────────────────────────────────────────────
//
// startClickHouse, runMigrations, chExec, chInsert and chQueryRows run the
// deployment's image with an open `default` account and apply the
// migrations statement by statement over HTTP. They remain only for tests
// that have not moved to startProdClickHouse (clickhouse_harness_test.go),
// which runs the repository's users-override.xml and migrate.sh as the
// migrate account: killswitch_audit_integration_test.go.

func startClickHouse(t *testing.T) string {
	return startClickHouseContainer(t, nil)
}

// startClickHouseContainer starts the deployment's clickhouse-server image
// with its storage.xml (migration 018 requires the `tiered` policy; the cold
// disk's endpoint does not resolve, which skip_access_check tolerates) and
// an open `default` account with access management.
func startClickHouseContainer(t *testing.T, customize func(*testcontainers.ContainerRequest)) string {
	t.Helper()
	ctx := context.Background()

	storage := filepath.Join(t.TempDir(), "storage.xml")
	if err := os.WriteFile(storage, []byte(clickhouseConfig(t)["storage.xml"]), 0o644); err != nil {
		t.Fatal(err)
	}
	req := testcontainers.ContainerRequest{
		Image:        clickhouseImage(t),
		ExposedPorts: []string{"8123/tcp"},
		Env:          map[string]string{"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1"},
		Files: []testcontainers.ContainerFile{{
			HostFilePath:      storage,
			ContainerFilePath: "/etc/clickhouse-server/config.d/storage.xml",
			FileMode:          0o644,
		}},
		WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp"),
	}
	if customize != nil {
		customize(&req)
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start clickhouse container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate clickhouse: %v", err)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("clickhouse host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8123/tcp")
	if err != nil {
		t.Fatalf("clickhouse port: %v", err)
	}

	return fmt.Sprintf("http://%s:%s", host, port.Port())
}

func runMigrations(t *testing.T, chURL string) {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "deploy", "clickhouse", "migrations")
	for _, f := range migrationFiles(t) {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range splitStatements(string(data)) {
			if err := chExec(chURL, stmt); err != nil {
				t.Fatalf("migration %s: %v", f, err)
			}
		}
	}
}

// splitStatements splits a migration file into individual statements for the
// HTTP interface (one statement per request). "--" comment lines are dropped
// first: the production path (clickhouse-client --multiquery) parses them,
// but a naive ";" split would break on semicolons inside comment text.
func splitStatements(sql string) []string {
	var kept []string
	for _, line := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	var stmts []string
	for _, stmt := range strings.Split(strings.Join(kept, "\n"), ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts
}

func chExec(baseURL, query string) error {
	resp, err := http.Post(baseURL+"/", "text/plain", strings.NewReader(query))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}
	return nil
}

func chInsert(baseURL, database, table string, record any) error {
	body, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	body = append(body, '\n')

	query := fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)
	u := fmt.Sprintf("%s/?database=%s&query=%s", baseURL,
		url.QueryEscape(database), url.QueryEscape(query))

	resp, err := http.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, errBody)
	}
	return nil
}

func chQueryRows(baseURL, database, query string, dest any) error {
	fullQuery := query + " FORMAT JSON"
	u := fmt.Sprintf("%s/?database=%s&query=%s", baseURL,
		url.QueryEscape(database), url.QueryEscape(fullQuery))

	resp, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	return json.Unmarshal(envelope.Data, dest)
}

// ── The deployment's server ──────────────────────────────────────────────

// TestClickHouseSchema applies every migration the way the migration Job
// does (migrate.sh as the migrate account, on the deployment's image and
// configuration), checks the tables that exist afterwards, that the runner's
// record is complete and a second run changes nothing, and round-trips a row
// through each table a service writes, as that service's account.
func TestClickHouseSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	srv := startProdClickHouse(t, chOptions{})

	t.Run("AllTablesCreated", func(t *testing.T) {
		expected := []string{
			"alerts:ReplacingMergeTree", "audit_log:MergeTree", "detection_feedback:ReplacingMergeTree",
			"device_events:MergeTree", "devices:ReplacingMergeTree", "dns_queries:MergeTree",
			"ml_anomalies:ReplacingMergeTree", "ml_beacons:ReplacingMergeTree", "network_flows:View",
			"schema_migrations:MergeTree", "suricata_alerts:MergeTree", "suricata_dns:MergeTree",
			"suricata_tls:MergeTree", "zeek_conn:MergeTree", "zeek_dns:MergeTree", "zeek_http:MergeTree",
			"zeek_intel:MergeTree", "zeek_ssl:MergeTree", "zeek_x509:MergeTree",
		}
		var tables []struct {
			Name   string `json:"name"`
			Engine string `json:"engine"`
		}
		if err := srv.query("migrate",
			"SELECT name, engine FROM system.tables WHERE database = 'netsoldier' ORDER BY name", &tables); err != nil {
			t.Fatalf("list tables: %v", err)
		}
		var got []string
		for _, tbl := range tables {
			got = append(got, tbl.Name+":"+tbl.Engine)
		}
		if strings.Join(got, " ") != strings.Join(expected, " ") {
			t.Fatalf("tables\n got %v\nwant %v", got, expected)
		}
	})

	t.Run("RunnerRecordAndRerun", func(t *testing.T) {
		files := migrationFiles(t)
		if n := srv.count(t, "migrate", "SELECT count() AS n FROM schema_migrations"); n != len(files) {
			t.Errorf("schema_migrations has %d rows, %d files exist", n, len(files))
		}
		out, code := srv.migrate(t, "", "apply")
		if code != 0 || !strings.Contains(out, "nothing to apply") {
			t.Errorf("second run: exit %d\n%s", code, out)
		}
		if out, code := srv.migrate(t, "", "status"); code != 0 {
			t.Errorf("status after apply: exit %d\n%s", code, out)
		}
	})

	t.Run("AlertRoundtrip", func(t *testing.T) {
		srv.mustInsert(t, "detection", "alerts", map[string]any{
			"timestamp": "2026-05-20 10:00:00", "observed_at": "2026-05-20 09:59:58.250",
			"id": "DET-INT-1", "summary": "DNS query for malware.evil.com matches threatfox domain indicator evil.com",
			"domain": "malware.evil.com", "client_ip": "192.168.1.42", "client_mac": "aa:bb:cc:dd:ee:ff",
			"query_type": "A", "matched_ioc": "evil.com", "ioc_type": "domain", "severity": "critical",
			"source": "threatfox", "signal_class": "ioc", "confidence": 95, "target_type": "domain",
			"target_value": "evil.com", "suppressed": 0,
		})
		var rows []struct {
			ID, Domain, ClientMAC, Severity, Summary, ObservedAt string
		}
		if err := srv.query("grafana", "SELECT id AS ID, domain AS Domain, client_mac AS ClientMAC, severity AS Severity, "+
			"summary AS Summary, toString(observed_at) AS ObservedAt FROM alerts WHERE id = 'DET-INT-1'", &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].ClientMAC != "aa:bb:cc:dd:ee:ff" || rows[0].ObservedAt != "2026-05-20 09:59:58.250" ||
			rows[0].Summary == "" {
			t.Fatalf("alerts: %+v", rows)
		}
	})

	t.Run("DeviceEventRoundtrip", func(t *testing.T) {
		srv.mustInsert(t, "inventory", "device_events", map[string]any{
			"timestamp": "2026-05-20 10:00:00.123", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.100",
			"hostname": "iot-sensor", "vendor": "Espressif", "protocol": "dhcp", "event_type": "seen",
		})
		if n := srv.count(t, "grafana", "SELECT count() AS n FROM device_events WHERE mac = 'aa:bb:cc:dd:ee:ff'"); n != 1 {
			t.Fatalf("device_events: %d rows", n)
		}
	})

	t.Run("DNSQueryRoundtrip", func(t *testing.T) {
		srv.mustInsert(t, "detection", "dns_queries", map[string]any{
			"timestamp": time.Now().Unix(), "client_ip": "192.168.1.42", "domain": "google.com",
			"query_type": "A", "answer": "142.250.80.46", "status": "NOERROR", "response_ms": 12,
			"blocked": 0, "reason": "NotFilteredNotFound", "threat_source": "", "threat_name": "",
		})
		var rows []struct {
			Domain string `json:"domain"`
			Reason string `json:"reason"`
		}
		if err := srv.query("inventory", "SELECT domain, reason FROM dns_queries WHERE client_ip = '192.168.1.42'", &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Domain != "google.com" || rows[0].Reason != "NotFilteredNotFound" {
			t.Fatalf("dns_queries: %+v", rows)
		}
	})

	t.Run("FlowViewOverZeekConn", func(t *testing.T) {
		srv.mustInsert(t, "zeek", "zeek_conn", map[string]any{
			"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05"), "uid": "CflowView1", "src_ip": "192.168.1.100",
			"src_port": 54321, "dst_ip": "1.1.1.1", "dst_port": 443, "proto": "tcp", "service": "ssl",
			"duration_ms": 500, "orig_bytes": 2048, "resp_bytes": 1024, "conn_state": "SF", "local_orig": 1,
			"local_resp": 0, "history": "ShADadFf", "orig_pkts": 15, "resp_pkts": 10,
		}, map[string]any{
			"timestamp": time.Now().UTC().Format("2006-01-02 15:04:05"), "uid": "CflowView2", "src_ip": "fd00::5",
			"dst_ip": "2001:db8::1", "proto": "icmp", "orig_pkts": 1, "resp_pkts": 1,
		})
		var rows []struct {
			UID      string      `json:"uid"`
			Protocol json.Number `json:"protocol"`
			BytesIn  json.Number `json:"bytes_in"`
			BytesOut json.Number `json:"bytes_out"`
			PktsOut  json.Number `json:"packets_out"`
		}
		if err := srv.query("inventory", "SELECT uid, protocol, bytes_in, bytes_out, packets_out FROM network_flows "+
			"WHERE uid IN ('CflowView1', 'CflowView2') ORDER BY uid", &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].Protocol.String() != "6" || rows[0].BytesIn.String() != "1024" ||
			rows[0].BytesOut.String() != "2048" || rows[0].PktsOut.String() != "15" || rows[1].Protocol.String() != "58" {
			t.Fatalf("network_flows over zeek_conn: %+v (want bytes_out = the originator's, ICMPv6 = 58)", rows)
		}
	})

	t.Run("AuditLogRoundtrip", func(t *testing.T) {
		srv.mustInsert(t, "killswitch", "audit_log", map[string]any{
			"timestamp": "2026-05-20 10:00:00.250", "action_id": "KS-INT-1", "from_state": "pending",
			"to_state": "active", "actor": "auto", "reason": "confidence >= 90", "detection_id": "DET-INT-1",
			"target_mac": "aa:bb:cc:dd:ee:ff", "target_ip": "192.168.1.100", "action_type": "dns_sinkhole",
		})
		if n := srv.count(t, "grafana", "SELECT count() AS n FROM audit_log WHERE action_id = 'KS-INT-1'"); n != 1 {
			t.Fatalf("audit_log: %d rows", n)
		}
	})

	// Each account holds the grants its code uses and no more. The vector
	// account in particular: a users.xml account without a <grants> element
	// has every privilege, and its grants were removed in step 125.10.
	t.Run("Grants", func(t *testing.T) {
		denied := []struct{ account, query string }{
			{"vector", "INSERT INTO dns_queries (domain) VALUES ('x')"},
			{"vector", "INSERT INTO alerts (id) VALUES ('x')"},
			{"vector", "SELECT count() FROM zeek_conn"},
			{"detection", "SELECT count() FROM dns_queries"},
			{"detection", "SELECT count() FROM alerts"},
			{"detection", "INSERT INTO zeek_conn (uid) VALUES ('x')"},
			{"inventory", "INSERT INTO alerts (id) VALUES ('x')"},
			{"inventory", "SELECT count() FROM audit_log"},
			{"zeek", "INSERT INTO suricata_alerts (src_ip) VALUES ('x')"},
			{"grafana", "INSERT INTO alerts (id) VALUES ('x')"},
			{"grafana", "DROP TABLE alerts"},
			{"migrate", "CREATE USER intruder IDENTIFIED WITH no_password"},
			{"migrate", "SELECT count() FROM system.users"},
		}
		for _, d := range denied {
			if err := srv.exec(d.account, d.query); err == nil || !strings.Contains(err.Error(), "ACCESS_DENIED") &&
				!strings.Contains(err.Error(), "Not enough privileges") {
				t.Errorf("%s: %q = %v, want access denied", d.account, d.query, err)
			}
		}
	})
}

// TestDeviceInventoryClickHouse verifies device-inventory runs against the
// deployment's ClickHouse with its own account: it checks its tables, comes
// up ready and serves its API. The service used to create its own tables at
// start-up; the schema belongs to the migrations alone.
func TestDeviceInventoryClickHouse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	srv := startProdClickHouse(t, chOptions{})

	invBin := goBuild(t, repoRoot(t), "apps/device-inventory")
	invAddr := freeAddr(t)
	stopInv := startProc(t, invBin, map[string]string{
		"LISTEN_ADDR":             invAddr,
		"DB_PATH":                 filepath.Join(t.TempDir(), "devices.db"),
		"CLICKHOUSE_URL":          srv.URL,
		"CLICKHOUSE_DATABASE":     "netsoldier",
		"CLICKHOUSE_USER":         "inventory",
		"CLICKHOUSE_PASSWORD":     srv.passwords["inventory"],
		"DEVICE_API_KEY":          e2eAPIKey,
		"NETAGENT_EXPECT_CAPTURE": "none",
	})
	t.Cleanup(stopInv)

	waitHealthy(t, "http://"+invAddr+"/healthz")
	waitHealthy(t, "http://"+invAddr+"/readyz")

	var devices []json.RawMessage
	httpGetJSONBearer(t, "http://"+invAddr+"/devices", e2eAPIKey, &devices)
	t.Logf("/devices: %d entries (0 expected)", len(devices))
}
