//go:build integration

package e2e

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// optionalPanels are dashboard queries allowed to return no data from the
// fixtures below, each with the reason. Keyed by "<dashboard uid>/<panel
// title>". Every other query must return at least one row with a value in
// it (a count of 0 or a NULL maximum is not data).
var optionalPanels = map[string]string{}

// The fixture household: one device, its traffic as the sensors write it,
// its DNS lookups as AdGuard logs them, and the enforcement history.
const (
	fxDevice    = "192.168.1.50"
	fxDeviceMAC = "3c:22:fb:00:00:50"
	fxOther     = "192.168.1.51"
	fxC2        = "c2.evil-ioc.test"
	fxFP        = "fp.evil-ioc.test" // an indicator an analyst marked false positive
	fxBlocked   = "ads.tracker.test"
	fxC2IP      = "203.0.113.7"
	fxWebIP     = "198.51.100.9"
)

// TestEveryDashboardAndServiceQueryHasData is step 125.10's check (audit
// DP-11, DP-26): the tables the web UI and the dashboards read have real
// writers, and every query reads something.
//
// ClickHouse is the deployment's (users-override.xml, migrate.sh as the
// migrate account). The sensor tables get rows as their sidecars write them,
// each with its own account. device-inventory and detection-engine run as
// built, with their own accounts: device-inventory writes devices and
// device_events from an ARP frame netagent would post, detection-engine
// writes alerts and dns_queries from a querylog AdGuard would serve. Then
// every dashboard query, extracted from the ConfigMaps, runs as the grafana
// account, and the device-inventory views the web UI shows are read through
// its API.
func TestEveryDashboardAndServiceQueryHasData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	queries := dashboardQueries(t)
	srv := startProdClickHouse(t, chOptions{})
	now := time.Now().UTC().Truncate(time.Second)
	seedSensorTables(t, srv, now)

	root := repoRoot(t)
	invAddr := startInventoryWithDevice(t, root, srv)
	startDetectionEngineOnQueryLog(t, root, srv, invAddr, now)

	// What detection-engine writes arrives in batches: wait for all of it.
	deadline := time.Now().Add(90 * time.Second)
	for {
		ioc := srv.count(t, "grafana", "SELECT count() AS n FROM alerts WHERE signal_class = 'ioc'")
		sup := srv.count(t, "grafana", "SELECT count() AS n FROM alerts WHERE suppressed = 1")
		dns := srv.count(t, "grafana", "SELECT count() AS n FROM dns_queries")
		dev := srv.count(t, "grafana", "SELECT count() AS n FROM devices")
		if ioc >= 2 && sup >= 1 && dns >= 4 && dev >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("writers did not deliver: alerts(ioc) %d (want 2), suppressed %d (want 1), dns_queries %d (want 4), devices %d",
				ioc, sup, dns, dev)
		}
		time.Sleep(time.Second)
	}

	from, to := now.Add(-6*time.Hour), time.Now().UTC().Add(time.Minute)
	t.Run("dashboards", func(t *testing.T) {
		seen := map[string]bool{}
		for _, q := range queries {
			if seen[q.key()] {
				t.Errorf("%s: two queries share the key %s", q, q.key())
			}
			seen[q.key()] = true
			sql, err := expandMacros(q.SQL, from, to, dashboardVars)
			if err != nil {
				t.Errorf("%s: %v", q, err)
				continue
			}
			rows, err := srv.rows("grafana", sql)
			if err != nil {
				t.Errorf("%s: %v\n%s", q, err, sql)
				continue
			}
			if reason, ok := optionalPanels[q.key()]; ok {
				t.Logf("%s: optional (%s), %d rows", q, reason, len(rows))
				continue
			}
			if !hasData(rows) {
				t.Errorf("%s: no data from the fixtures (rows %v)\n%s", q, rows, sql)
			}
		}
		for k := range optionalPanels {
			if !seen[k] {
				t.Errorf("optionalPanels names %s, which no dashboard has any more", k)
			}
		}
	})

	t.Run("device views", func(t *testing.T) {
		base := "http://" + invAddr + "/devices/" + fxDeviceMAC
		var conns []struct {
			DstIP     string `json:"dst_ip"`
			DstDomain string `json:"dst_domain"`
			Protocol  int    `json:"protocol"`
			BytesIn   uint64 `json:"bytes_in"`
		}
		httpGetJSONBearer(t, base+"/connections", e2eAPIKey, &conns)
		domains := map[string]string{}
		for _, c := range conns {
			domains[c.DstIP] = c.DstDomain
		}
		if len(conns) < 3 || domains[fxC2IP] != "api.example.net" || domains[fxWebIP] != "plain.example.org" {
			t.Errorf("connections: %+v (want the TLS server name and the HTTP host as destination names)", conns)
		}
		var dns []struct {
			Domain  string `json:"domain"`
			Blocked int    `json:"blocked"`
		}
		httpGetJSONBearer(t, base+"/dns", e2eAPIKey, &dns)
		blocked := false
		for _, d := range dns {
			blocked = blocked || (d.Domain == fxBlocked && d.Blocked == 1)
		}
		if len(dns) < 4 || !blocked {
			t.Errorf("dns: %+v", dns)
		}
		var alerts []struct {
			ID         string `json:"id"`
			Summary    string `json:"summary"`
			MatchedIoC string `json:"matched_ioc"`
			Suppressed bool   `json:"suppressed"`
		}
		httpGetJSONBearer(t, base+"/alerts", e2eAPIKey, &alerts)
		var c2, fp bool
		for _, a := range alerts {
			c2 = c2 || (a.MatchedIoC == fxC2 && a.Summary != "" && !a.Suppressed)
			fp = fp || (a.MatchedIoC == fxFP && a.Suppressed)
		}
		if !c2 || !fp {
			t.Errorf("alerts: %+v (want the C2 lookup, and the false positive marked suppressed)", alerts)
		}
		var topo struct {
			Edges []struct {
				Source     string `json:"source"`
				Target     string `json:"target"`
				TotalBytes uint64 `json:"total_bytes"`
			} `json:"edges"`
		}
		httpGetJSONBearer(t, "http://"+invAddr+"/topology?hours=6", e2eAPIKey, &topo)
		edge := false
		for _, e := range topo.Edges {
			edge = edge || (e.Source == fxDevice && e.Target == fxC2IP && e.TotalBytes > 0)
		}
		if !edge {
			t.Errorf("topology has no edge %s -> %s: %+v", fxDevice, fxC2IP, topo.Edges)
		}
	})
}

// rows runs a SELECT as account and returns its rows as JSON objects.
func (s *chServer) rows(account, query string) ([]map[string]any, error) {
	var out []map[string]any
	err := s.query(account, query, &out)
	return out, err
}

// hasData reports whether any cell holds a value: not 0, "", "0" or NULL.
func hasData(rows []map[string]any) bool {
	for _, r := range rows {
		for _, v := range r {
			switch x := v.(type) {
			case nil:
			case float64:
				if x != 0 {
					return true
				}
			case string:
				if x != "" && x != "0" && x != "nan" {
					return true
				}
			case bool:
				if x {
					return true
				}
			default:
				return true
			}
		}
	}
	return false
}

func chTime(t time.Time) string   { return t.UTC().Format("2006-01-02 15:04:05") }
func chTime64(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }

// seedSensorTables writes what Zeek, Suricata, the ML workers and the
// killswitch write, each as its own account.
func seedSensorTables(t *testing.T, srv *chServer, now time.Time) {
	t.Helper()
	conn := func(uid, src, dst string, dport int, proto, service string, ago time.Duration, out, in uint64) map[string]any {
		return map[string]any{"timestamp": chTime(now.Add(-ago)), "uid": uid, "src_ip": src, "src_port": 50000 + dport%1000,
			"dst_ip": dst, "dst_port": dport, "proto": proto, "service": service, "duration_ms": 1500,
			"orig_bytes": out, "resp_bytes": in, "conn_state": "SF", "local_orig": 1, "local_resp": 0,
			"history": "ShADadFf", "orig_pkts": 20, "resp_pkts": 50}
	}
	srv.mustInsert(t, "zeek", "zeek_conn",
		conn("Cfx1", fxDevice, fxC2IP, 443, "tcp", "ssl", 10*time.Minute, 2048, 65536),
		conn("Cfx2", fxDevice, "192.168.1.1", 53, "udp", "dns", 9*time.Minute, 60, 120),
		conn("Cfx3", fxDevice, fxWebIP, 80, "tcp", "http", 8*time.Minute, 512, 4096),
		conn("Cfx4", fxOther, "203.0.113.8", 443, "tcp", "ssl", 7*time.Minute, 1024, 2048))
	ssl := func(uid, src, dst, sni, version, fp string, ago time.Duration) map[string]any {
		return map[string]any{"timestamp": chTime(now.Add(-ago)), "uid": uid, "src_ip": src, "src_port": 50443,
			"dst_ip": dst, "dst_port": 443, "version": version, "cipher": "TLS_AES_128_GCM_SHA256", "curve": "x25519",
			"server_name": sni, "resumed": 0, "established": 1, "subject": "CN=" + sni, "issuer": "CN=Fixture CA",
			"ja3": "e7d705a3286e19ea42f587b344ee6865", "ja3s": "", "tls_client_fp": fp}
	}
	srv.mustInsert(t, "zeek", "zeek_ssl",
		ssl("Cfx1", fxDevice, fxC2IP, "api.example.net", "TLSv13", "t13d1516h2_8daaf6152771_e5627efa2ab1", 10*time.Minute),
		ssl("Cfx4", fxOther, "203.0.113.8", "", "TLSv10", "t10d070600_c50f5591e341_1a3805c3aa63", 7*time.Minute))
	srv.mustInsert(t, "zeek", "zeek_http", map[string]any{"timestamp": chTime(now.Add(-8 * time.Minute)), "uid": "Cfx3",
		"src_ip": fxDevice, "src_port": 50080, "dst_ip": fxWebIP, "dst_port": 80, "method": "GET",
		"host": "plain.example.org", "uri": "/", "referrer": "", "user_agent": "curl/8.5.0", "status_code": 200,
		"request_body_len": 0, "response_body_len": 1234})
	srv.mustInsert(t, "zeek", "zeek_x509", map[string]any{"timestamp": chTime(now.Add(-10 * time.Minute)),
		"fingerprint": "5f1e2c0d9a", "serial": "01", "subject": "CN=api.example.net", "issuer": "CN=Fixture CA",
		"not_valid_before": chTime(now.Add(-24 * time.Hour)), "not_valid_after": chTime(now.Add(10 * 24 * time.Hour)),
		"key_alg": "rsaEncryption", "key_length": 2048, "san_dns": []string{"api.example.net"}})
	srv.mustInsert(t, "zeek", "zeek_intel", map[string]any{"timestamp": chTime(now.Add(-10 * time.Minute)), "uid": "Cfx1",
		"src_ip": fxDevice, "src_port": 50443, "dst_ip": fxC2IP, "dst_port": 443,
		"indicator": "e7d705a3286e19ea42f587b344ee6865", "indicator_type": "Intel::JA3", "seen_where": "SSL::IN_JA3",
		"matched": []string{"Intel::JA3"}, "sources": []string{"fixture-feed"}})
	srv.mustInsert(t, "zeek", "zeek_dns", map[string]any{"timestamp": chTime(now.Add(-11 * time.Minute)), "uid": "Cfx2",
		"src_ip": fxDevice, "src_port": 50053, "dst_ip": "192.168.1.1", "dst_port": 53, "proto": "udp",
		"query": "api.example.net", "qtype_name": "A", "rcode_name": "NOERROR", "answers": []string{fxC2IP}, "rejected": 0})

	srv.mustInsert(t, "suricata", "suricata_alerts", map[string]any{"timestamp": chTime(now.Add(-10 * time.Minute)),
		"flow_id": 4242, "src_ip": fxDevice, "src_port": 50443, "dest_ip": fxC2IP, "dest_port": 443, "proto": "TCP",
		"alert_action": "allowed", "alert_gid": 1, "alert_signature_id": 2000001, "alert_rev": 1,
		"alert_signature": "ET MALWARE Fixture C2 Beacon", "alert_category": "A Network Trojan was detected",
		"alert_severity": 1, "app_proto": "tls"})

	srv.mustInsert(t, "ml_beacon", "ml_beacons", map[string]any{"timestamp": chTime(now.Add(-5 * time.Minute)),
		"src_ip": fxDevice, "dst_ip": fxC2IP, "dst_domain": "", "beacon_score": 0.95, "connection_count": 120,
		"confidence": 85, "severity": "high", "beacon_type": "ip", "tags": []string{"rita"}})
	srv.mustInsert(t, "ml_flow", "ml_anomalies", map[string]any{"timestamp": chTime(now.Add(-10 * time.Minute)),
		"window_start": chTime(now.Add(-20 * time.Minute)), "src_ip": fxDevice, "anomaly_score": 0.81, "confidence": 60,
		"severity": "medium", "conn_count": 340, "bytes_out": 52428800, "bytes_in": 1048576, "dst_fanout": 12,
		"port_fanout": 3, "avg_duration_ms": 850.5, "model_version": "fixture-1", "tags": []string{"volumetric"}})

	// Three actions: approved by a person and active; still pending; and
	// automatic, active, then reverted by a person.
	audit := func(id, from, to, actor string, ago time.Duration) map[string]any {
		return map[string]any{"timestamp": chTime64(now.Add(-ago)), "action_id": id, "from_state": from, "to_state": to,
			"actor": actor, "reason": "fixture", "detection_id": "DET-fx-1", "target_mac": fxDeviceMAC,
			"target_ip": fxDevice, "action_type": "dns_sinkhole", "blocked_domain": fxC2, "policy_rule": "manual",
			"detection_summary": "DNS query for " + fxC2}
	}
	srv.mustInsert(t, "killswitch", "audit_log",
		audit("KS-fx-1", "", "pending", "system", 30*time.Minute),
		audit("KS-fx-1", "pending", "approved", "alice", 28*time.Minute),
		audit("KS-fx-1", "approved", "active", "alice", 27*time.Minute),
		audit("KS-fx-2", "", "pending", "system", 20*time.Minute),
		audit("KS-fx-3", "", "approved", "auto-policy", 15*time.Minute),
		audit("KS-fx-3", "approved", "active", "auto-policy", 14*time.Minute),
		audit("KS-fx-3", "active", "reverted", "bob", 5*time.Minute))
}

// startInventoryWithDevice runs device-inventory against srv as the
// inventory account and has the fixture device announce itself with an ARP
// reply, posted the way netagent posts captured frames.
func startInventoryWithDevice(t *testing.T, root string, srv *chServer) string {
	t.Helper()
	bin := goBuild(t, root, "apps/device-inventory")
	addr := freeAddr(t)
	t.Cleanup(startProc(t, bin, map[string]string{
		"LISTEN_ADDR":             addr,
		"DB_PATH":                 filepath.Join(t.TempDir(), "devices.db"),
		"CLICKHOUSE_URL":          srv.URL,
		"CLICKHOUSE_USER":         "inventory",
		"CLICKHOUSE_PASSWORD":     srv.passwords["inventory"],
		"DEVICE_API_KEY":          e2eAPIKey,
		"NETAGENT_TOKEN":          e2eAgentToken,
		"NETAGENT_EXPECT_CAPTURE": "none",
	}))
	waitHealthy(t, "http://"+addr+"/healthz")

	body, _ := json.Marshal(map[string]any{
		"agent": "e2e", "interface": "lan0",
		"frames":  []map[string]any{{"t": time.Now().UnixNano(), "proto": "arp", "data": arpReply(t, fxDeviceMAC, fxDevice)}},
		"results": []any{},
		"status":  map[string]any{"capture": map[string]bool{"arp": true}, "dropped": 0},
	})
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/agent/v1/frames", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e2eAgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /agent/v1/frames: %d %s", resp.StatusCode, b)
	}
	var dev struct {
		MAC string `json:"mac"`
	}
	httpGetJSONBearer(t, "http://"+addr+"/devices/by-ip/"+fxDevice, e2eAPIKey, &dev)
	if dev.MAC != fxDeviceMAC {
		t.Fatalf("device-inventory has %q at %s, want %s", dev.MAC, fxDevice, fxDeviceMAC)
	}
	return addr
}

// arpReply builds an Ethernet/ARP reply in which mac announces ip.
func arpReply(t *testing.T, mac, ip string) []byte {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	f := make([]byte, 0, 42)
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, hw...)
	f = binary.BigEndian.AppendUint16(f, 0x0806)
	f = binary.BigEndian.AppendUint16(f, 1)      // Ethernet
	f = binary.BigEndian.AppendUint16(f, 0x0800) // IPv4
	f = append(f, 6, 4)
	f = binary.BigEndian.AppendUint16(f, 2) // reply
	f = append(f, hw...)
	f = append(f, net.ParseIP(ip).To4()...)
	f = append(f, make([]byte, 6)...)
	f = append(f, net.ParseIP("192.168.1.1").To4()...)
	return f
}

// startDetectionEngineOnQueryLog runs detection-engine against srv as the
// detection account, reading a querylog with a C2 lookup, a false positive
// an analyst has already marked, a blocked tracker and an ordinary lookup.
func startDetectionEngineOnQueryLog(t *testing.T, root string, srv *chServer, invAddr string, now time.Time) {
	t.Helper()
	threats := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(threats, []byte(fxC2+"\n"+fxFP+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := func(name, reason, elapsed string, ago time.Duration, answers ...string) map[string]any {
		var ans []map[string]any
		for _, a := range answers {
			ans = append(ans, map[string]any{"type": "A", "value": a, "ttl": 300})
		}
		return map[string]any{"question": map[string]string{"name": name, "type": "A", "class": "IN"},
			"client": fxDevice, "time": now.Add(-ago), "reason": reason, "status": "NOERROR",
			"elapsedMs": elapsed, "answer": ans}
	}
	var released atomic.Bool
	ag := startMockAdGuardWith(t, released.Load,
		entry("www.example.org", "NotFilteredNotFound", "3.1", 20*time.Second, "93.184.216.34"),
		entry(fxBlocked, "FilteredBlackList", "0.4", 30*time.Second, "0.0.0.0"),
		entry(fxFP, "NotFilteredNotFound", "8.0", 40*time.Second, "192.0.2.10"),
		entry(fxC2, "NotFilteredNotFound", "15.2", 50*time.Second, fxC2IP))

	bin := goBuild(t, root, "apps/detection-engine")
	addr := freeAddr(t)
	t.Cleanup(startProc(t, bin, map[string]string{
		"LISTEN_ADDR":          addr,
		"DB_PATH":              filepath.Join(t.TempDir(), "detection-engine.db"),
		"ADGUARD_URL":          ag.url,
		"ADGUARD_USER":         "admin",
		"ADGUARD_PASSWORD":     "test",
		"THREATLIST_PATH":      threats,
		"POLL_INTERVAL":        "1s",
		"SENSOR_POLL_INTERVAL": "1s",
		"CLICKHOUSE_URL":       srv.URL,
		"CLICKHOUSE_USER":      "detection",
		"CLICKHOUSE_PASSWORD":  srv.passwords["detection"],
		"DEVICE_INVENTORY_URL": "http://" + invAddr,
		"DEVICE_API_KEY":       e2eAPIKey,
		"DETECTION_API_KEY":    e2eAPIKey,
		"LOCAL_NETWORKS":       "192.168.0.0/16",
	}))
	waitHealthy(t, "http://"+addr+"/healthz")

	// The analyst's verdict comes first, so the lookup of that indicator is
	// recorded as suppressed.
	body := fmt.Sprintf(`{"matched_ioc":%q,"signal_class":"ioc","verdict":"false_positive","reason":"fixture"}`, fxFP)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/feedback", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e2eAPIKey)
	req.Header.Set("X-Netsoldier-Actor", e2eActor)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST /feedback: %d %s", resp.StatusCode, b)
	}
	released.Store(true)
}
