package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

func newTestAPI(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	h := NewHandler(db, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", h.ListDevices)
	mux.HandleFunc("GET /devices/{mac}", h.GetDevice)
	mux.HandleFunc("PUT /devices/{mac}/labels", h.SetLabels)
	mux.HandleFunc("GET /devices/{mac}/connections", h.DeviceConnections)
	mux.HandleFunc("GET /devices/{mac}/dns", h.DeviceDNS)
	mux.HandleFunc("GET /devices/{mac}/alerts", h.DeviceAlerts)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv, db
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func TestListDevicesEmpty(t *testing.T) {
	srv, _ := newTestAPI(t)
	devices := getJSON[[]store.Device](t, srv.URL+"/devices")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devices))
	}
}

func TestListDevicesWithData(t *testing.T) {
	srv, db := newTestAPI(t)
	db.Upsert("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "", "", "Espressif")
	db.Upsert("11:22:33:44:55:66", "192.168.1.101", "laptop-1", "", "", "Apple")

	devices := getJSON[[]store.Device](t, srv.URL+"/devices")
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
}

func TestGetDevice(t *testing.T) {
	srv, db := newTestAPI(t)
	db.UpsertFull("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "fp1", "vc1", "Espressif", "FreeRTOS", "iot")

	resp, err := http.Get(srv.URL + "/devices/aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var device store.Device
	json.NewDecoder(resp.Body).Decode(&device)

	if device.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("mac: got %q", device.MAC)
	}
	if device.Hostname != "sensor-1" {
		t.Errorf("hostname: got %q", device.Hostname)
	}
	if device.OS != "FreeRTOS" {
		t.Errorf("os: got %q", device.OS)
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, err := http.Get(srv.URL + "/devices/ff:ff:ff:ff:ff:ff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestSetLabels(t *testing.T) {
	srv, db := newTestAPI(t)
	db.Upsert("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "", "", "Espressif")

	body := `{"labels":["critical","iot"]}`
	req, _ := http.NewRequest("PUT", srv.URL+"/devices/aa:bb:cc:dd:ee:ff/labels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var device store.Device
	json.NewDecoder(resp.Body).Decode(&device)
	if len(device.Labels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(device.Labels))
	}
	if device.Labels[0] != "critical" || device.Labels[1] != "iot" {
		t.Errorf("labels: got %v", device.Labels)
	}
}

func TestSetLabelsDeviceNotFound(t *testing.T) {
	srv, _ := newTestAPI(t)
	body := `{"labels":["test"]}`
	req, _ := http.NewRequest("PUT", srv.URL+"/devices/ff:ff:ff:ff:ff:ff/labels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestDeviceConnectionsNoClickHouse(t *testing.T) {
	srv, db := newTestAPI(t)
	db.Upsert("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "", "", "Espressif")

	resp, err := http.Get(srv.URL + "/devices/aa:bb:cc:dd:ee:ff/connections")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var rows []any
	json.NewDecoder(resp.Body).Decode(&rows)
	if len(rows) != 0 {
		t.Errorf("expected empty connections without ClickHouse, got %d", len(rows))
	}
}

func TestDeviceDNSNoClickHouse(t *testing.T) {
	srv, db := newTestAPI(t)
	db.Upsert("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "", "", "Espressif")

	resp, err := http.Get(srv.URL + "/devices/aa:bb:cc:dd:ee:ff/dns")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var rows []any
	json.NewDecoder(resp.Body).Decode(&rows)
	if len(rows) != 0 {
		t.Errorf("expected empty DNS without ClickHouse, got %d", len(rows))
	}
}

func TestDeviceAlertsNoClickHouse(t *testing.T) {
	srv, db := newTestAPI(t)
	db.Upsert("aa:bb:cc:dd:ee:ff", "192.168.1.100", "sensor-1", "", "", "Espressif")

	resp, err := http.Get(srv.URL + "/devices/aa:bb:cc:dd:ee:ff/alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var rows []any
	json.NewDecoder(resp.Body).Decode(&rows)
	if len(rows) != 0 {
		t.Errorf("expected empty alerts without ClickHouse, got %d", len(rows))
	}
}

func TestDeviceAlertsBadMAC(t *testing.T) {
	srv, _ := newTestAPI(t)
	resp, err := http.Get(srv.URL + "/devices/not-a-mac/alerts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 for invalid MAC, got %d", resp.StatusCode)
	}
}
