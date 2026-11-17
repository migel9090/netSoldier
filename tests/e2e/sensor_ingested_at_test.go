//go:build integration

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sensorTables are the tables detection-engine tails on (ingested_at, row
// hash) since migration 026.
var sensorTables = []string{"suricata_alerts", "zeek_intel", "zeek_ssl", "ml_beacons", "ml_anomalies"}

// TestSensorIngestedAtMigration applies 026 to a database that already holds
// sensor rows, on the image the deployment runs. Rows written before the
// migration must get their event time as arrival time — not the time of
// each read, and not one shared time that makes the whole history look new —
// and rows written after it the server's insert time, whatever event time
// they carry.
func TestSensorIngestedAtMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	srv := startProdClickHouse(t, chOptions{noMigrate: true})
	srv.migrateOnly(t, func(name string) bool { return name < "026" })

	week := time.Now().UTC().Add(-7 * 24 * time.Hour).Truncate(time.Second)
	for _, table := range sensorTables {
		srv.mustInsert(t, sensorWriter[table], table, sensorRow(table, week, "before"))
	}

	srv.migrateOnly(t, func(name string) bool { return name < "027" })

	type row struct {
		IA string `json:"ia"`
		TS string `json:"ts"`
	}
	read := func(table, marker string) row {
		t.Helper()
		var rows []row
		q := fmt.Sprintf("SELECT toString(toUnixTimestamp64Milli(ingested_at)) AS ia, toString(toUnixTimestamp(timestamp)*1000) AS ts "+
			"FROM netsoldier.%s WHERE %s", table, markerFilter(table, marker))
		if err := srv.query("migrate", q, &rows); err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s %s: %d rows", table, marker, len(rows))
		}
		return rows[0]
	}
	first := map[string]row{}
	for _, table := range sensorTables {
		r := read(table, "before")
		if r.IA != r.TS {
			t.Errorf("%s: a row from before the migration has ingested_at %s, want its event time %s", table, r.IA, r.TS)
		}
		first[table] = r
	}
	time.Sleep(1100 * time.Millisecond)
	for _, table := range sensorTables {
		if r := read(table, "before"); r.IA != first[table].IA {
			t.Errorf("%s: ingested_at of an old row moved between reads (%s -> %s): evaluated at read time",
				table, first[table].IA, r.IA)
		}
	}

	// Written after the migration with the same week-old event time: the
	// arrival time is now.
	for _, table := range sensorTables {
		srv.mustInsert(t, sensorWriter[table], table, sensorRow(table, week, "after"))
		r := read(table, "after")
		ia, _ := strconv.ParseInt(r.IA, 10, 64)
		if d := time.Since(time.UnixMilli(ia)); d < -time.Minute || d > time.Minute {
			t.Errorf("%s: a new row with a week-old event time has ingested_at %s, want about now", table, time.UnixMilli(ia).UTC())
		}
	}

	// system.data_skipping_indices is for the administrator only.
	idx := strings.Fields(srv.admin(t, "SELECT table FROM system.data_skipping_indices "+
		"WHERE database = 'netsoldier' AND name = 'ingested_at_minmax' ORDER BY table"))
	if len(idx) != len(sensorTables) {
		t.Errorf("minmax index on %d tables (%v), want %d", len(idx), idx, len(sensorTables))
	}

	// The runner re-applies a file that failed part-way from the top.
	applyMigrationAgain(t, srv, "026_")
}

// sensorWriter is the account that writes each sensor table.
var sensorWriter = map[string]string{
	"suricata_alerts": "suricata", "zeek_intel": "zeek", "zeek_ssl": "zeek",
	"ml_beacons": "ml_beacon", "ml_anomalies": "ml_flow",
}

// applyMigrationAgain runs the statements of the migration whose name starts
// with prefix once more, as the migrate account: what the runner does with a
// file that failed part-way. It must succeed and change nothing.
func applyMigrationAgain(t *testing.T, srv *chServer, prefix string) {
	t.Helper()
	for _, name := range migrationFiles(t) {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "clickhouse", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range splitStatements(string(data)) {
			if err := srv.exec("migrate", stmt); err != nil {
				t.Fatalf("re-running %s: %v", name, err)
			}
		}
		return
	}
	t.Fatalf("no migration %s*", prefix)
}

func sensorRow(table string, eventTime time.Time, marker string) map[string]any {
	ts := eventTime.Format("2006-01-02 15:04:05")
	switch table {
	case "suricata_alerts":
		return map[string]any{"timestamp": ts, "flow_id": 1, "src_ip": "192.168.1.50", "src_port": 1,
			"dest_ip": "203.0.113.7", "dest_port": 443, "proto": "TCP", "alert_signature": "ET MALWARE " + marker,
			"alert_category": "x", "alert_severity": 1, "alert_signature_id": 1}
	case "zeek_intel":
		return map[string]any{"timestamp": ts, "uid": marker, "src_ip": "192.168.1.50", "src_port": 1,
			"dst_ip": "192.168.1.2", "dst_port": 53, "indicator": "x.example", "indicator_type": "Intel::DOMAIN",
			"seen_where": "DNS::IN_REQUEST", "matched": []string{}, "sources": []string{"t"}}
	case "zeek_ssl":
		return map[string]any{"timestamp": ts, "uid": marker, "src_ip": "192.168.1.50", "src_port": 1,
			"dst_ip": "203.0.113.7", "dst_port": 443, "server_name": "x.example", "established": 1}
	case "ml_beacons":
		return map[string]any{"timestamp": ts, "src_ip": "192.168.1.50", "dst_ip": "", "dst_domain": marker + ".example",
			"beacon_score": 0.9, "connection_count": 10, "confidence": 70, "severity": "high", "tags": []string{}}
	default: // ml_anomalies
		return map[string]any{"timestamp": ts, "window_start": ts, "src_ip": "192.168.1.50", "anomaly_score": 0.9,
			"confidence": 60, "severity": "high", "conn_count": 1, "bytes_out": 1, "bytes_in": 1, "dst_fanout": 1,
			"port_fanout": 1, "avg_duration_ms": 1, "model_version": marker, "tags": []string{}}
	}
}

func markerFilter(table, marker string) string {
	switch table {
	case "suricata_alerts":
		return fmt.Sprintf("alert_signature = 'ET MALWARE %s'", marker)
	case "zeek_intel", "zeek_ssl":
		return fmt.Sprintf("uid = '%s'", marker)
	case "ml_beacons":
		return fmt.Sprintf("dst_domain = '%s.example'", marker)
	default:
		return fmt.Sprintf("model_version = '%s'", marker)
	}
}
