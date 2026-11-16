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
	if err := client.CheckSchema(ctx, "devices", "device_events", "connections", "network_flows"); err != nil {
		t.Fatal(err)
	}
	ip := fmt.Sprintf("192.168.250.%d", time.Now().Second()+1)
	now := time.Now().UTC()
	conn := map[string]any{
		"timestamp": now.Format(ch.SecondsLayout), "src_mac": "aa:bb:cc:dd:ee:01", "src_ip": ip,
		"dst_ip": "1.1.1.1", "dst_domain": "one.one", "dst_port": 443, "protocol": 6,
		"bytes_in": uint64(1) << 40, "bytes_out": 42, "duration_ms": 7,
	}
	flow := map[string]any{
		"timestamp": now.Format(ch.SecondsLayout), "src_ip": ip, "dst_ip": "1.1.1.1", "dst_port": 443, "protocol": 6,
		"bytes_in": uint64(1) << 40, "bytes_out": 1, "packets_in": 10, "packets_out": 1,
	}
	if err := client.Insert(ctx, "connections", conn); err != nil {
		t.Fatal(err)
	}
	if err := client.Insert(ctx, "network_flows", flow); err != nil {
		t.Fatal(err)
	}

	srv, db := newTestAPI(t, client)
	seen(t, db, arp("aa:bb:cc:dd:ee:01", ip))

	code, _, body := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:01/connections")
	if code != 200 || !strings.Contains(string(body), `"bytes_in":1099511627776`) {
		t.Errorf("connections: %d %s", code, body)
	}
	topo := getJSON[topoResponse](t, srv.URL+"/topology")
	found := false
	for _, e := range topo.Edges {
		if e.Source == ip && e.TotalBytes == 1<<40+1 && e.FlowCount >= 1 {
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
