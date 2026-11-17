//go:build integration

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestRebuildMigrationsKeepRows applies 032 (ml_beacons keyed on the
// destination name too) and 033 (alerts a ReplacingMergeTree again) to a
// database that already holds rows, as the migration Job does, and checks
// what each rebuild is for and that it loses nothing — including when the
// runner re-applies a file from the top after it failed part-way.
func TestRebuildMigrationsKeepRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	srv := startProdClickHouse(t, chOptions{noMigrate: true})
	srv.migrateOnly(t, func(name string) bool { return name < "032" })

	// Two SNI beacons of one device stamped with the same second: ml-anomaly
	// writes no address for them, only the name. With the old key one of
	// them disappeared at the next merge (or at once, written together).
	// Written apart, both are still there when the migration copies them.
	ts := chTime(time.Now().UTC().Add(-time.Hour))
	beacon := func(domain string) map[string]any {
		return map[string]any{"timestamp": ts, "src_ip": "192.168.1.50", "dst_ip": "", "dst_domain": domain,
			"beacon_score": 0.93, "connection_count": 50, "confidence": 80, "severity": "high",
			"beacon_type": "sni", "tags": []string{}}
	}
	srv.mustInsert(t, "ml_beacon", "ml_beacons", beacon("a.c2.test"))
	srv.mustInsert(t, "ml_beacon", "ml_beacons", beacon("b.c2.test"))
	var before []struct {
		Domain string `json:"dst_domain"`
		IA     string `json:"ia"`
	}
	if err := srv.query("migrate", "SELECT dst_domain, toString(ingested_at) AS ia FROM ml_beacons ORDER BY dst_domain", &before); err != nil {
		t.Fatal(err)
	}

	// An alert copied twice (a crash between the insert and saving the
	// copy's position).
	alert := map[string]any{"timestamp": ts, "id": "DET-rb-1", "domain": "a.c2.test", "client_ip": "192.168.1.50",
		"query_type": "A", "matched_ioc": "c2.test", "severity": "high", "source": "threatfox", "signal_class": "ioc"}
	srv.mustInsert(t, "detection", "alerts", alert)
	srv.mustInsert(t, "detection", "alerts", alert)

	srv.migrateOnly(t, func(string) bool { return true })

	check := func(when string) {
		t.Helper()
		var key []struct {
			Table  string `json:"name"`
			Engine string `json:"engine"`
			Key    string `json:"sorting_key"`
		}
		if err := srv.query("migrate", "SELECT name, engine, sorting_key FROM system.tables WHERE database = 'netsoldier' "+
			"AND name IN ('alerts', 'ml_beacons') ORDER BY name", &key); err != nil {
			t.Fatal(err)
		}
		if len(key) != 2 || key[0].Engine != "ReplacingMergeTree" || key[0].Key != "timestamp, id" ||
			key[1].Key != "timestamp, src_ip, dst_ip, dst_domain" {
			t.Fatalf("%s: %+v", when, key)
		}
		// The index detection-engine's cursor relies on (026) is part of the
		// rebuilt table.
		if n := strings.TrimSpace(srv.admin(t, "SELECT count() FROM system.data_skipping_indices WHERE database = 'netsoldier' "+
			"AND table = 'ml_beacons' AND name = 'ingested_at_minmax'")); n != "1" {
			t.Errorf("%s: ml_beacons has %s ingested_at_minmax indexes, want 1", when, n)
		}
		srv.admin(t, "OPTIMIZE TABLE netsoldier.ml_beacons FINAL")
		srv.admin(t, "OPTIMIZE TABLE netsoldier.alerts FINAL")
		var after []struct {
			Domain string `json:"dst_domain"`
			IA     string `json:"ia"`
		}
		if err := srv.query("migrate", "SELECT dst_domain, toString(ingested_at) AS ia FROM ml_beacons ORDER BY dst_domain", &after); err != nil {
			t.Fatal(err)
		}
		if len(after) != 2 || len(before) != 2 || after[0] != before[0] || after[1] != before[1] {
			t.Errorf("%s: ml_beacons %+v, want %+v (both beacons, arrival times unchanged)", when, after, before)
		}
		if n := srv.count(t, "migrate", "SELECT count() AS n FROM alerts WHERE id = 'DET-rb-1'"); n != 1 {
			t.Errorf("%s: alert copied twice is %d rows after a merge, want 1", when, n)
		}
		if n := srv.count(t, "migrate", "SELECT count() AS n FROM system.tables WHERE database = 'netsoldier' "+
			"AND (name LIKE '%\\_032%' OR name LIKE '%\\_033%')"); n != 0 {
			t.Errorf("%s: %d staging tables left", when, n)
		}
	}
	check("after the migrations")

	applyMigrationAgain(t, srv, "032_")
	applyMigrationAgain(t, srv, "033_")
	check("after re-running them")

	out, code := srv.migrate(t, "", "status")
	if code != 0 || !strings.Contains(out, "up to date") {
		t.Errorf("status: exit %d\n%s", code, out)
	}
}
