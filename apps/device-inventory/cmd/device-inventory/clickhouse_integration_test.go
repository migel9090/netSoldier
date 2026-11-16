package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

// TestRealClickHouseWrites is DI-5's write half against a real server: the
// service's writer must land device_events (millisecond timestamps, the
// DateTime64(3) column of migration 023) and devices snapshots. Skipped
// unless DEVICE_INVENTORY_CH_TEST_URL is set.
func TestRealClickHouseWrites(t *testing.T) {
	u := os.Getenv("DEVICE_INVENTORY_CH_TEST_URL")
	if u == "" {
		t.Skip("DEVICE_INVENTORY_CH_TEST_URL not set")
	}
	client := ch.NewClient(u, "netsoldier", os.Getenv("DEVICE_INVENTORY_CH_TEST_USER"), os.Getenv("DEVICE_INVENTORY_CH_TEST_PASSWORD"))

	db, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w := newCHWriter(client, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	mac := fmt.Sprintf("02:00:00:00:%02x:%02x", time.Now().Second(), time.Now().Nanosecond()%256)
	handleSighting(db, w, discovery.Sighting{Source: discovery.SourceDHCP, MAC: mac, IP: "192.168.251.7",
		Name: "ch-roundtrip", Fingerprint: "1,3,6,15", VendorClass: "udhcp 1.36"})
	if _, err := db.SetLabels(mac, []string{"lab"}); err != nil {
		t.Fatal(err)
	}
	d, _ := db.GetDevice(mac)
	w.device(d)
	cancel()
	<-done

	var events []struct {
		TS        string `json:"ts"`
		EventType string `json:"event_type"`
	}
	if err := client.Query(context.Background(),
		`SELECT toString(timestamp) AS ts, event_type FROM device_events WHERE mac = {mac:String}`,
		&events, map[string]string{"mac": mac}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].EventType != "new" || len(events[0].TS) != len(ch.MillisLayout) {
		t.Errorf("device_events: %+v (timestamp must keep milliseconds)", events)
	}

	var devices []struct {
		Hostname string    `json:"hostname"`
		IP       string    `json:"ip"`
		Labels   []string  `json:"labels"`
		Versions ch.UInt64 `json:"versions"`
	}
	if err := client.Query(context.Background(),
		`SELECT argMax(hostname, updated_at) AS hostname, argMax(ip, updated_at) AS ip,
			argMax(labels, updated_at) AS labels, count() AS versions
		FROM devices WHERE mac = {mac:String}`, &devices, map[string]string{"mac": mac}); err != nil {
		t.Fatal(err)
	}
	// Two snapshots were written (new device, labels); a background merge
	// may already have collapsed them.
	if len(devices) != 1 || devices[0].Hostname != "ch-roundtrip" || devices[0].IP != "192.168.251.7" || devices[0].Versions < 1 {
		t.Errorf("devices: %+v", devices)
	}
}
