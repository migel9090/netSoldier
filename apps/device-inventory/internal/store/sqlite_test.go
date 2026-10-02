package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "devices.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIsRandomizedMAC(t *testing.T) {
	randomized := []string{
		"aa:bb:cc:dd:ee:ff", // 0xaa -> bit 1 set
		"02:00:00:00:00:01",
		"06-11-22-33-44-55",
		"3a:1f:2b:00:00:01",
	}
	for _, m := range randomized {
		if !IsRandomizedMAC(m) {
			t.Errorf("IsRandomizedMAC(%q) = false, want true", m)
		}
	}

	stable := []string{
		"00:11:22:33:44:55", // real OUI
		"b8:27:eb:00:00:01", // Raspberry Pi
		"", "garbage", "zz:11:22:33:44:55", "0:11:22:33:44:55",
	}
	for _, m := range stable {
		if IsRandomizedMAC(m) {
			t.Errorf("IsRandomizedMAC(%q) = true, want false", m)
		}
	}
}

func TestUpsertAndGet(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertFull("00:11:22:33:44:55", "192.168.1.10", "nas",
		"1,3,6", "MSFT 5.0", "Acme", "Linux", "nas"); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	d, err := s.GetDevice("00:11:22:33:44:55")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if d == nil {
		t.Fatal("device not found")
	}
	if d.Hostname != "nas" || d.IP != "192.168.1.10" || d.Vendor != "Acme" {
		t.Errorf("unexpected device: %+v", d)
	}
}

func TestUpsertDoesNotClearFieldsWithEmptyValues(t *testing.T) {
	s := newTestStore(t)
	mac := "00:11:22:33:44:55"
	if err := s.UpsertFull(mac, "192.168.1.10", "nas", "1,3,6", "MSFT 5.0",
		"Acme", "Linux", "nas"); err != nil {
		t.Fatal(err)
	}
	// A later sighting from ARP carries only the MAC.
	if err := s.Upsert(mac, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}

	d, _ := s.GetDevice(mac)
	if d.Hostname != "nas" || d.Vendor != "Acme" || d.IP != "192.168.1.10" {
		t.Errorf("a partial sighting must not erase known fields: %+v", d)
	}
}

// TestStableIDCannotHijackStableDevice is the regression test for the
// inventory takeover. stable_id comes from DHCP options 60 and 12, which the
// client chooses freely, and the correlating UPDATE rewrites a row's MAC. A
// malicious device copying a neighbour's vendor class and hostname could
// re-point that record at itself — inheriting its labels while the real
// device disappeared from the inventory.
func TestStableIDCannotHijackStableDevice(t *testing.T) {
	s := newTestStore(t)

	victimMAC := "b8:27:eb:11:22:33" // real OUI, not randomized
	if err := s.UpsertFull(victimMAC, "192.168.1.10", "homeassistant",
		"1,3,6,15", "udhcp 1.30", "Raspberry Pi", "Linux", "iot"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLabels(victimMAC, []string{"critical", "trusted"}); err != nil {
		t.Fatal(err)
	}

	// Attacker uses a randomized MAC and copies the victim's DHCP identity.
	attackerMAC := "aa:bb:cc:dd:ee:ff"
	if err := s.UpsertFull(attackerMAC, "192.168.1.99", "homeassistant",
		"1,3,6,15", "udhcp 1.30", "", "", ""); err != nil {
		t.Fatal(err)
	}

	victim, err := s.GetDevice(victimMAC)
	if err != nil {
		t.Fatal(err)
	}
	if victim == nil {
		t.Fatal("the victim device was removed from the inventory — its record was hijacked")
	}
	if victim.IP != "192.168.1.10" {
		t.Errorf("victim IP was rewritten to %q", victim.IP)
	}
	if len(victim.Labels) != 2 {
		t.Errorf("victim labels were inherited by the attacker: %v", victim.Labels)
	}

	attacker, err := s.GetDevice(attackerMAC)
	if err != nil {
		t.Fatal(err)
	}
	if attacker == nil {
		t.Fatal("the attacker should exist as its own separate record")
	}
	if len(attacker.Labels) != 0 {
		t.Errorf("attacker must not inherit labels: %v", attacker.Labels)
	}
}

// TestRandomizedMACRotationStillCorrelates: the legitimate feature must keep
// working — one privacy MAC replacing another on the same physical device.
func TestRandomizedMACRotationStillCorrelates(t *testing.T) {
	s := newTestStore(t)

	first := "aa:bb:cc:00:00:01"
	if err := s.UpsertFull(first, "192.168.1.20", "iphone",
		"1,3,6", "iPhone", "Apple", "iOS", "phone"); err != nil {
		t.Fatal(err)
	}

	// Same device after a MAC rotation.
	second := "ae:bb:cc:00:00:02"
	if err := s.UpsertFull(second, "192.168.1.21", "iphone",
		"1,3,6", "iPhone", "Apple", "iOS", "phone"); err != nil {
		t.Fatal(err)
	}

	devices, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 {
		t.Fatalf("a MAC rotation should update one record, got %d devices", len(devices))
	}
	if devices[0].MAC != second {
		t.Errorf("record should carry the new MAC, got %q", devices[0].MAC)
	}
}

func TestStableIDRequiresVendorClass(t *testing.T) {
	s := newTestStore(t)
	// Hostname alone must not be enough to move a device record.
	if err := s.UpsertFull("aa:bb:cc:00:00:01", "192.168.1.20", "shared-name",
		"", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertFull("ae:bb:cc:00:00:02", "192.168.1.21", "shared-name",
		"", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	devices, _ := s.List()
	if len(devices) != 2 {
		t.Errorf("hostname-only correlation should not merge records, got %d", len(devices))
	}
}

// TestEnrichByIPCannotRenameDevice: mDNS/SSDP are unauthenticated, so any
// device can claim any IP. Enrichment may fill a blank, never overwrite.
func TestEnrichByIPCannotRenameDevice(t *testing.T) {
	s := newTestStore(t)
	routerMAC := "00:11:22:33:44:01"
	if err := s.UpsertFull(routerMAC, "192.168.1.1", "router",
		"", "", "Vendor", "", "gateway"); err != nil {
		t.Fatal(err)
	}

	if err := s.EnrichByIP("192.168.1.1", "definitely-not-the-router"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice(routerMAC)
	if d.Hostname != "router" {
		t.Errorf("hostname was overwritten by an unauthenticated announcement: %q", d.Hostname)
	}
}

func TestEnrichByIPFillsMissingHostname(t *testing.T) {
	s := newTestStore(t)
	mac := "00:11:22:33:44:02"
	if err := s.Upsert(mac, "192.168.1.30", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.EnrichByIP("192.168.1.30", "printer"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice(mac)
	if d.Hostname != "printer" {
		t.Errorf("a blank hostname should be filled by enrichment, got %q", d.Hostname)
	}
}

func TestSetLabelsRequiresKnownDevice(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetLabels("00:00:00:00:00:99", []string{"x"}); err == nil {
		t.Error("labelling an unknown device should fail")
	}
}

func TestPruneRemovesStaleUnlabelledDevices(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("00:11:22:33:44:01", "192.168.1.10", "old", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert("00:11:22:33:44:02", "192.168.1.11", "labelled", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetLabels("00:11:22:33:44:02", []string{"keep"}); err != nil {
		t.Fatal(err)
	}

	// Everything is "now", so a negative age makes both rows stale.
	removed, err := s.Prune(-time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 (labelled devices are kept)", removed)
	}
	if d, _ := s.GetDevice("00:11:22:33:44:02"); d == nil {
		t.Error("a labelled device must survive pruning")
	}
}

func TestPruneKeepsFreshDevices(t *testing.T) {
	s := newTestStore(t)
	if err := s.Upsert("00:11:22:33:44:01", "192.168.1.10", "fresh", "", "", ""); err != nil {
		t.Fatal(err)
	}
	removed, err := s.Prune(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}

func TestCount(t *testing.T) {
	s := newTestStore(t)
	for _, mac := range []string{"00:11:22:33:44:01", "00:11:22:33:44:02"} {
		if err := s.Upsert(mac, "", "", "", "", ""); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("Count() = %d, want 2", n)
	}
}

func TestStableIDDeterministic(t *testing.T) {
	a := StableID("MSFT 5.0", "laptop")
	b := StableID("MSFT 5.0", "laptop")
	c := StableID("MSFT 5.0", "desktop")
	if a != b {
		t.Error("StableID should be deterministic")
	}
	if a == c {
		t.Error("different hostnames should produce different IDs")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Upsert("00:11:22:33:44:01", "10.0.0.1", "x", "", "", ""); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	// Re-opening runs the migrations again against an existing schema.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen should succeed: %v", err)
	}
	defer s2.Close()
	if n, _ := s2.Count(); n != 1 {
		t.Errorf("data should survive reopen, Count() = %d", n)
	}
}
