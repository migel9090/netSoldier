package api

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
)

// chFromEnv returns a writer-credentialed client for a real ClickHouse that
// already has the netsoldier schema (the migration Job's tables, with
// device_events.timestamp as DateTime64(3)). The test is skipped unless
// DEVICE_INVENTORY_CH_TEST_URL is set, so `go test ./...` stays hermetic.
func chFromEnv(t *testing.T) *ch.Client {
	t.Helper()
	u := os.Getenv("DEVICE_INVENTORY_CH_TEST_URL")
	if u == "" {
		t.Skip("DEVICE_INVENTORY_CH_TEST_URL not set")
	}
	return ch.NewClient(u, "netsoldier", os.Getenv("DEVICE_INVENTORY_CH_TEST_USER"), os.Getenv("DEVICE_INVENTORY_CH_TEST_PASSWORD"))
}

// TestRealClickHouseViews is DI-5 against a real server: write rows with the
// service's own client and read them back through the HTTP handlers, where
// quoted UInt64 values used to make every view silently empty.
func TestRealClickHouseViews(t *testing.T) {
	client := chFromEnv(t)
	ctx := context.Background()
	if err := client.CheckSchema(ctx, "devices", "device_events", "network_flows", "zeek_conn", "zeek_ssl"); err != nil {
		t.Fatal(err)
	}
	ip := fmt.Sprintf("192.168.250.%d", time.Now().Second()+1)
	now := time.Now().UTC()
	uid := fmt.Sprintf("C%d", now.UnixNano())
	// Flows come from Zeek's conn.log (network_flows is a view over
	// zeek_conn since migration 028); the destination's name from ssl.log.
	conn := map[string]any{
		"timestamp": now.Format(ch.SecondsLayout), "uid": uid, "src_ip": ip, "src_port": 50000,
		"dst_ip": "1.1.1.1", "dst_port": 443, "proto": "tcp", "service": "ssl",
		"duration_ms": 7, "orig_bytes": 1, "resp_bytes": uint64(1) << 40, "conn_state": "SF",
		"local_orig": 1, "local_resp": 0, "history": "ShADadFf", "orig_pkts": 1, "resp_pkts": 10,
	}
	sni := map[string]any{
		"timestamp": now.Format(ch.SecondsLayout), "uid": uid, "src_ip": ip, "src_port": 50000,
		"dst_ip": "1.1.1.1", "dst_port": 443, "server_name": "one.one", "established": 1,
	}
	if err := client.Insert(ctx, "zeek_conn", conn); err != nil {
		t.Fatal(err)
	}
	if err := client.Insert(ctx, "zeek_ssl", sni); err != nil {
		t.Fatal(err)
	}

	srv, db := newTestAPI(t, client)
	seen(t, db, arp("aa:bb:cc:dd:ee:01", ip))

	code, _, body := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:01/connections")
	if code != 200 || !strings.Contains(string(body), `"bytes_in":1099511627776`) ||
		!strings.Contains(string(body), `"dst_domain":"one.one"`) || !strings.Contains(string(body), `"protocol":6`) {
		t.Errorf("connections: %d %s", code, body)
	}
	topo := getJSON[topoResponse](t, srv.URL+"/topology")
	found := false
	for _, e := range topo.Edges {
		if e.Source == ip && e.TotalBytes == 1<<40+1 && e.FlowCount >= 1 && e.TotalPackets == 11 {
			found = true
		}
	}
	if !found {
		t.Errorf("topology has no edge from %s: %+v", ip, topo.Edges)
	}
	for _, view := range []string{"dns", "alerts"} {
		if code, _, body := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:01/"+view); code != 200 {
			t.Errorf("%s: %d %s", view, code, body)
		}
	}

	bad := ch.NewClient(os.Getenv("DEVICE_INVENTORY_CH_TEST_URL"), "netsoldier", "writer", "wrong-password")
	if err := bad.Insert(ctx, "device_events", ch.DeviceEvent{Timestamp: now.Format(ch.MillisLayout)}); err == nil {
		t.Error("a wrong password must fail")
	}
}
