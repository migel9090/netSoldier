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
	"sort"
	"strings"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startClickHouse(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "clickhouse/clickhouse-server:24.8",
			ExposedPorts: []string{"8123/tcp"},
			Env:          map[string]string{"CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT": "1"},
			WaitingFor:   wait.ForHTTP("/ping").WithPort("8123/tcp"),
		},
		Started: true,
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

	root := repoRoot(t)
	dir := filepath.Join(root, "deploy", "clickhouse", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}

	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range strings.Split(string(data), ";") {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if err := chExec(chURL, stmt); err != nil {
				t.Fatalf("migration %s: %v", f, err)
			}
		}
	}
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

// TestClickHouseSchema verifies all migrations run cleanly against a real
// ClickHouse server and tests insert+query roundtrips for each critical table.
func TestClickHouseSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	chURL := startClickHouse(t)
	runMigrations(t, chURL)

	t.Run("AllTablesCreated", func(t *testing.T) {
		expected := []string{
			"alerts", "audit_log", "connections", "device_events",
			"devices", "dns_queries", "events", "network_flows",
		}

		type tableRow struct {
			Name string `json:"name"`
		}
		var tables []tableRow
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT name FROM system.tables WHERE database = 'netsoldier' ORDER BY name",
			&tables); err != nil {
			t.Fatalf("list tables: %v", err)
		}

		var got []string
		for _, tbl := range tables {
			got = append(got, tbl.Name)
		}

		if len(got) != len(expected) {
			t.Fatalf("expected %d tables, got %d: %v", len(expected), len(got), got)
		}
		for i, want := range expected {
			if got[i] != want {
				t.Errorf("table[%d] = %q, want %q", i, got[i], want)
			}
		}
	})

	t.Run("AlertRoundtrip", func(t *testing.T) {
		if err := chInsert(chURL, "netsoldier", "alerts", map[string]any{
			"timestamp":   "2026-05-20 10:00:00",
			"id":          "DET-INT-1",
			"domain":      "malware.evil.com",
			"client_ip":   "192.168.1.42",
			"query_type":  "A",
			"matched_ioc": "evil.com",
			"severity":    "critical",
			"source":      "threatfox",
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}

		type row struct {
			ID       string `json:"id"`
			Domain   string `json:"domain"`
			ClientIP string `json:"client_ip"`
			Severity string `json:"severity"`
			Source   string `json:"source"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT id, domain, client_ip, severity, source FROM alerts WHERE id = 'DET-INT-1'",
			&rows); err != nil {
			t.Fatalf("query: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		assertEq(t, "id", "DET-INT-1", rows[0].ID)
		assertEq(t, "domain", "malware.evil.com", rows[0].Domain)
		assertEq(t, "client_ip", "192.168.1.42", rows[0].ClientIP)
		assertEq(t, "severity", "critical", rows[0].Severity)
		assertEq(t, "source", "threatfox", rows[0].Source)
	})

	t.Run("DeviceEventRoundtrip", func(t *testing.T) {
		if err := chInsert(chURL, "netsoldier", "device_events", map[string]any{
			"timestamp":  "2026-05-20 10:00:00",
			"mac":        "aa:bb:cc:dd:ee:ff",
			"ip":         "192.168.1.100",
			"hostname":   "iot-sensor",
			"vendor":     "Espressif",
			"protocol":   "dhcp",
			"event_type": "seen",
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}

		type row struct {
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			Protocol string `json:"protocol"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT mac, ip, hostname, protocol FROM device_events WHERE mac = 'aa:bb:cc:dd:ee:ff'",
			&rows); err != nil {
			t.Fatalf("query: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		assertEq(t, "mac", "aa:bb:cc:dd:ee:ff", rows[0].MAC)
		assertEq(t, "ip", "192.168.1.100", rows[0].IP)
		assertEq(t, "hostname", "iot-sensor", rows[0].Hostname)
		assertEq(t, "protocol", "dhcp", rows[0].Protocol)
	})

	t.Run("DNSQueryRoundtrip", func(t *testing.T) {
		if err := chInsert(chURL, "netsoldier", "dns_queries", map[string]any{
			"timestamp":   "2026-05-20 10:00:00",
			"client_ip":   "192.168.1.42",
			"domain":      "google.com",
			"query_type":  "A",
			"answer":      "142.250.80.46",
			"status":      "noerror",
			"response_ms": 12,
			"blocked":     0,
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}

		type row struct {
			Domain    string `json:"domain"`
			ClientIP  string `json:"client_ip"`
			QueryType string `json:"query_type"`
			Answer    string `json:"answer"`
			Blocked   int    `json:"blocked"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT domain, client_ip, query_type, answer, blocked FROM dns_queries WHERE domain = 'google.com'",
			&rows); err != nil {
			t.Fatalf("query: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		assertEq(t, "domain", "google.com", rows[0].Domain)
		assertEq(t, "client_ip", "192.168.1.42", rows[0].ClientIP)
		assertEq(t, "answer", "142.250.80.46", rows[0].Answer)
		if rows[0].Blocked != 0 {
			t.Errorf("blocked: want 0, got %d", rows[0].Blocked)
		}
	})

	t.Run("ConnectionRoundtrip", func(t *testing.T) {
		if err := chInsert(chURL, "netsoldier", "connections", map[string]any{
			"timestamp":       "2026-05-20 10:00:00",
			"src_mac":         "aa:bb:cc:dd:ee:ff",
			"src_hostname":    "iot-sensor",
			"src_vendor":      "Espressif",
			"src_os":          "FreeRTOS",
			"src_device_type": "iot",
			"src_ip":          "192.168.1.100",
			"src_port":        54321,
			"dst_ip":          "1.1.1.1",
			"dst_domain":      "one.one.one.one",
			"dst_port":        443,
			"protocol":        6,
			"bytes_in":        1024,
			"bytes_out":       2048,
			"packets_in":      10,
			"packets_out":     15,
			"duration_ms":     500,
			"tcp_flags":       18,
			"vlan_id":         0,
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}

		type row struct {
			SrcMAC    string `json:"src_mac"`
			SrcIP     string `json:"src_ip"`
			DstIP     string `json:"dst_ip"`
			DstDomain string `json:"dst_domain"`
			DstPort   int    `json:"dst_port,string"`
			BytesIn   int    `json:"bytes_in,string"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT src_mac, src_ip, dst_ip, dst_domain, dst_port, bytes_in FROM connections WHERE src_mac = 'aa:bb:cc:dd:ee:ff'",
			&rows); err != nil {
			t.Fatalf("query: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		assertEq(t, "src_mac", "aa:bb:cc:dd:ee:ff", rows[0].SrcMAC)
		assertEq(t, "dst_domain", "one.one.one.one", rows[0].DstDomain)
		if rows[0].DstPort != 443 {
			t.Errorf("dst_port: want 443, got %d", rows[0].DstPort)
		}
		if rows[0].BytesIn != 1024 {
			t.Errorf("bytes_in: want 1024, got %d", rows[0].BytesIn)
		}
	})

	t.Run("AuditLogRoundtrip", func(t *testing.T) {
		if err := chInsert(chURL, "netsoldier", "audit_log", map[string]any{
			"timestamp":    "2026-05-20 10:00:00",
			"action_id":    "KS-INT-1",
			"from_state":   "pending",
			"to_state":     "active",
			"actor":        "auto",
			"reason":       "confidence >= 90",
			"detection_id": "DET-INT-1",
			"target_mac":   "aa:bb:cc:dd:ee:ff",
			"target_ip":    "192.168.1.100",
			"action_type":  "dns_sinkhole",
		}); err != nil {
			t.Fatalf("insert: %v", err)
		}

		type row struct {
			ActionID    string `json:"action_id"`
			FromState   string `json:"from_state"`
			ToState     string `json:"to_state"`
			Actor       string `json:"actor"`
			DetectionID string `json:"detection_id"`
			ActionType  string `json:"action_type"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT action_id, from_state, to_state, actor, detection_id, action_type FROM audit_log WHERE action_id = 'KS-INT-1'",
			&rows); err != nil {
			t.Fatalf("query: %v", err)
		}

		if len(rows) != 1 {
			t.Fatalf("expected 1 row, got %d", len(rows))
		}
		assertEq(t, "action_id", "KS-INT-1", rows[0].ActionID)
		assertEq(t, "from_state", "pending", rows[0].FromState)
		assertEq(t, "to_state", "active", rows[0].ToState)
		assertEq(t, "action_type", "dns_sinkhole", rows[0].ActionType)
		assertEq(t, "detection_id", "DET-INT-1", rows[0].DetectionID)
	})
}

// TestDeviceInventoryClickHouse verifies device-inventory starts and initializes
// its ClickHouse schema when connected to a real ClickHouse server.
func TestDeviceInventoryClickHouse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	chURL := startClickHouse(t)

	root := repoRoot(t)
	invBin := goBuild(t, root, "apps/device-inventory")

	invAddr := freeAddr(t)
	stopInv := startProc(t, invBin, map[string]string{
		"LISTEN_ADDR":         invAddr,
		"DB_PATH":             filepath.Join(t.TempDir(), "devices.db"),
		"CLICKHOUSE_URL":      chURL,
		"CLICKHOUSE_DATABASE": "netsoldier",
	})
	t.Cleanup(stopInv)

	waitHealthy(t, "http://"+invAddr+"/healthz")

	type tableRow struct {
		Name string `json:"name"`
	}
	var tables []tableRow
	if err := chQueryRows(chURL, "netsoldier",
		"SELECT name FROM system.tables WHERE database = 'netsoldier' ORDER BY name",
		&tables); err != nil {
		t.Fatalf("query tables: %v", err)
	}

	want := map[string]bool{"devices": false, "device_events": false}
	for _, tbl := range tables {
		if _, ok := want[tbl.Name]; ok {
			want[tbl.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("InitSchema did not create table %q", name)
		}
	}

	// /devices should return valid (empty) response
	var devices []json.RawMessage
	httpGetJSON(t, "http://"+invAddr+"/devices", &devices)
	t.Logf("/devices: %d entries (0 expected)", len(devices))
}
