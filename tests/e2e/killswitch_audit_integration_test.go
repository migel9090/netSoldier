//go:build integration

package e2e

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// TestKillswitchAuditReachesClickHouse runs the real killswitch against a
// ClickHouse whose schema the migrations built (audit_log.timestamp is
// DateTime64(3) after 023). Audit writes were best-effort and every one of
// them was refused by the old DateTime column; here every transition must
// arrive, with the millisecond it happened at and the actor who caused it.
func TestKillswitchAuditReachesClickHouse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	chURL := startClickHouse(t)
	runMigrations(t, chURL)

	ksBin := goBuild(t, repoRoot(t), "apps/killswitch-controller")
	ag := startMockAdGuard(t, time.Now().Add(time.Minute))
	ksAddr := freeAddr(t)
	t.Cleanup(startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
		"ALLOWLIST_IPS":           "192.168.1.1",
		"CLICKHOUSE_URL":          chURL,
		"CLICKHOUSE_DATABASE":     "netsoldier",
	}))
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	var res struct {
		Action *events.EnforcementAction `json:"action"`
	}
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, v2Event("audit-ch.example", 97, events.SeverityCritical), &res)
	if res.Action == nil || res.Action.State != events.StateActive {
		t.Fatalf("setup: %+v", res.Action)
	}
	id := res.Action.ID
	req, _ := http.NewRequest(http.MethodPost, "http://"+ksAddr+"/actions/"+id+"/revert", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer "+e2eAPIKey)
	req.Header.Set("X-Netsoldier-Actor", "alice")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 200 {
		t.Fatalf("revert: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}

	type row struct {
		TS        string `json:"ts"`
		FromState string `json:"from_state"`
		ToState   string `json:"to_state"`
		Actor     string `json:"actor"`
		Detection string `json:"detection_id"`
		TargetIP  string `json:"target_ip"`
	}
	var rows []row
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		rows = nil
		if err := chQueryRows(chURL, "netsoldier", "SELECT toString(timestamp) AS ts, from_state, to_state, actor, "+
			"detection_id, target_ip FROM audit_log WHERE action_id = '"+id+"' ORDER BY timestamp, to_state", &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 3 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if len(rows) != 3 {
		t.Fatalf("ClickHouse has %d of 3 audit rows: %+v", len(rows), rows)
	}

	var local []struct {
		Timestamp time.Time `json:"timestamp"`
		ToState   string    `json:"to_state"`
	}
	httpGetJSON(t, "http://"+ksAddr+"/audit?action_id="+id, &local)
	want := map[string]string{}
	for _, e := range local {
		want[e.ToState] = e.Timestamp.UTC().Format("2006-01-02 15:04:05.000")
	}
	got := []string{}
	for _, r := range rows {
		got = append(got, r.FromState+">"+r.ToState+":"+r.Actor)
		if r.TS != want[r.ToState] {
			t.Errorf("%s: ClickHouse has %s, the local log %s — milliseconds must survive", r.ToState, r.TS, want[r.ToState])
		}
		if r.Detection == "" || r.TargetIP == "" {
			t.Errorf("row without its detection or target: %+v", r)
		}
	}
	if strings.Join(got, " ") != ">approved:auto-policy approved>active:auto-policy active>reverted:alice" {
		t.Errorf("audit rows: %v", got)
	}
	var col []struct {
		Type string `json:"type"`
	}
	chQueryRows(chURL, "netsoldier", "SELECT type FROM system.columns WHERE database = 'netsoldier' "+
		"AND table = 'audit_log' AND name = 'timestamp'", &col)
	if len(col) != 1 || col[0].Type != "DateTime64(3)" {
		t.Errorf("audit_log.timestamp is %+v", col)
	}
}
