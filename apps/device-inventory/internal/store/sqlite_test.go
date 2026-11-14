package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// clock is a settable time source; sightings at one instant coalesce, so
// tests that repeat a sighting move the clock past Options.Coalesce.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore(t *testing.T, opts ...func(*Options)) (*Store, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	o := Options{Now: c.now}
	for _, f := range opts {
		f(&o)
	}
	s, err := OpenWithOptions(filepath.Join(t.TempDir(), "devices.db"), o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, c
}

func observe(t *testing.T, s *Store, o discovery.Sighting) Result {
	t.Helper()
	res, err := s.Observe(o)
	if err != nil {
		t.Fatalf("observe %+v: %v", o, err)
	}
	return res
}

func arpSeen(mac, ip string) discovery.Sighting {
	return discovery.Sighting{Source: discovery.SourceARP, MAC: mac, IP: ip}
}

func dhcpSeen(mac, ip, host, fp, vc string) discovery.Sighting {
	return discovery.Sighting{Source: discovery.SourceDHCP, MAC: mac, IP: ip, Name: host, Fingerprint: fp, VendorClass: vc}
}

func mustGet(t *testing.T, s *Store, mac string) *Device {
	t.Helper()
	d, err := s.GetDevice(mac)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatalf("device %s not found", mac)
	}
	return d
}

// confirm makes a binding live: the claim, then a re-confirmation from ARP
// after the coalescing window.
func confirm(t *testing.T, s *Store, c *clock, mac, ip string) {
	t.Helper()
	observe(t, s, arpSeen(mac, ip))
	c.advance(20 * time.Second)
	observe(t, s, arpSeen(mac, ip))
	if d := mustGet(t, s, mac); d.IP != ip || d.IPState != IPLive {
		t.Fatalf("binding %s=%s not live: ip=%q state=%q", mac, ip, d.IP, d.IPState)
	}
}

func TestObserveAndGet(t *testing.T) {
	s, _ := newTestStore(t)
	res := observe(t, s, dhcpSeen("00:11:22:33:44:55", "192.168.1.10", "nas", "1,3,6", "MSFT 5.0"))
	if res.Outcome != Applied || !res.Created || !res.Changed {
		t.Fatalf("unexpected result: %+v", res)
	}
	d := mustGet(t, s, "00:11:22:33:44:55")
	if d.Hostname != "nas" || d.HostnameSource != "dhcp" || d.IP != "192.168.1.10" ||
		d.IPState != IPTentative || d.Fingerprint != "1,3,6" || d.VendorClass != "MSFT 5.0" {
		t.Errorf("unexpected device: %+v", d)
	}
	if d.RandomizedMAC || d.Established || len(d.Labels) != 0 {
		t.Errorf("flags: %+v", d)
	}
}

func TestPartialSightingDoesNotClearFields(t *testing.T) {
	s, c := newTestStore(t)
	mac := "00:11:22:33:44:55"
	observe(t, s, dhcpSeen(mac, "192.168.1.10", "nas", "1,3,6", "MSFT 5.0"))
	c.advance(time.Minute)
	observe(t, s, discovery.Sighting{Source: discovery.SourceARP, MAC: mac}) // an ARP probe: MAC only

	d := mustGet(t, s, mac)
	if d.Hostname != "nas" || d.VendorClass != "MSFT 5.0" || d.IP != "192.168.1.10" {
		t.Errorf("a partial sighting must not erase known fields: %+v", d)
	}
}

func TestInvalidSightingsAreRefused(t *testing.T) {
	s, _ := newTestStore(t)
	for _, o := range []discovery.Sighting{
		{Source: discovery.SourceARP, MAC: "01:00:5e:00:00:01", IP: "192.168.1.2"},   // multicast MAC
		{Source: discovery.SourceARP, MAC: "00:00:00:00:00:00", IP: "192.168.1.2"},   // zero MAC
		{Source: discovery.SourceARP, MAC: "aa:bb:cc:dd:ee:ff:00:11", IP: "1.2.3.4"}, // hlen 8
		{Source: "bogus", MAC: "00:11:22:33:44:55"},
		{Source: discovery.SourceMDNS, IP: "192.168.1.2"},                   // name missing
		{Source: discovery.SourceMDNS, IP: "224.0.0.251", Name: "x"},        // not a host address
		{Source: discovery.SourceSSDP, Name: "x"},                           // no address
		{Source: discovery.SourceMDNS, IP: "192.168.1.2", Name: "\x00\x1b"}, // nothing printable
	} {
		if res := observe(t, s, o); res.Outcome != Invalid {
			t.Errorf("%+v: outcome %s, want invalid", o, res.Outcome)
		}
	}
	// An unusable address on a MAC claim drops the address, not the MAC.
	res := observe(t, s, arpSeen("00:11:22:33:44:55", "255.255.255.255"))
	if res.Outcome != Applied || res.Device.IP != "" {
		t.Errorf("unusable IP should be dropped: %+v", res.Device)
	}
	if s.Count() != 1 {
		t.Errorf("Count() = %d, want 1", s.Count())
	}
}

func TestNamesAreSanitizedAndBounded(t *testing.T) {
	s, _ := newTestStore(t)
	raw := "a\x00b\xff\x1b[31m\r\n<script>\u202e" + strings.Repeat("x", 300)
	observe(t, s, dhcpSeen("02:00:00:00:00:01", "", raw, "", "vc\x07\x00"))
	d := mustGet(t, s, "02:00:00:00:00:01")
	if strings.ContainsAny(d.Hostname, "\x00\x1b\r\n\u202e") || len(d.Hostname) > discovery.MaxNameLen {
		t.Errorf("hostname stored unsanitised: %q", d.Hostname)
	}
	if !strings.HasPrefix(d.Hostname, "ab[31m <script>") {
		t.Errorf("hostname = %q", d.Hostname)
	}
	if d.VendorClass != "vc" {
		t.Errorf("vendor class = %q", d.VendorClass)
	}
}

func TestSetLabels(t *testing.T) {
	s, _ := newTestStore(t)
	observe(t, s, arpSeen("00:11:22:33:44:55", "192.168.1.2"))

	d, err := s.SetLabels("00:11:22:33:44:55", []string{" critical ", "iot", "critical"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Labels, ",") != "critical,iot" || !d.Established {
		t.Errorf("labels trimmed and de-duplicated, device established: %+v", d)
	}

	if _, err := s.SetLabels("00:00:00:00:00:99", []string{"x"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown device: err = %v", err)
	}
	for _, bad := range [][]string{
		make([]string, MaxLabels+1),
		{strings.Repeat("a", MaxLabelLen+1)},
		{""},
		{"tab\there"},
		{"bidi\u202eflip"},
	} {
		for i := range bad {
			if bad[i] == "" && len(bad) > 1 {
				bad[i] = "x" + strings.Repeat("y", i%5)
			}
		}
		if _, err := s.SetLabels("00:11:22:33:44:55", bad); !errors.Is(err, ErrInvalidLabels) {
			t.Errorf("labels %q: err = %v, want ErrInvalidLabels", bad, err)
		}
	}
}

func TestPruneRemovesStaleUnlabelledDevices(t *testing.T) {
	s, c := newTestStore(t)
	observe(t, s, arpSeen("00:11:22:33:44:01", "192.168.1.10"))
	observe(t, s, arpSeen("00:11:22:33:44:02", "192.168.1.11"))
	if _, err := s.SetLabels("00:11:22:33:44:02", []string{"keep"}); err != nil {
		t.Fatal(err)
	}
	c.advance(48 * time.Hour)
	observe(t, s, arpSeen("00:11:22:33:44:03", "192.168.1.12"))

	removed, err := s.Prune(24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 (labelled and fresh devices are kept)", removed)
	}
	if d, _ := s.GetDevice("00:11:22:33:44:02"); d == nil {
		t.Error("a labelled device must survive pruning")
	}
	if s.Count() != 2 {
		t.Errorf("Count() = %d after prune, want 2", s.Count())
	}
}

func TestCountIsKeptInMemoryAndExact(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) { o.MaxDevices = 3 })
	for _, mac := range []string{"00:11:22:33:44:01", "00:11:22:33:44:02", "00:11:22:33:44:03", "00:11:22:33:44:04"} {
		observe(t, s, arpSeen(mac, ""))
		c.advance(time.Second)
	}
	c.advance(48 * time.Hour)
	if _, err := s.Prune(24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	observe(t, s, arpSeen("00:11:22:33:44:05", ""))
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM devices`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if s.Count() != n || n != 1 {
		t.Errorf("Count() = %d, table has %d, want 1", s.Count(), n)
	}
}

// DI-7: the sighting path must not scan the table. Lookups by MAC, by
// address and of a device's conflicts all use an index.
func TestSightingPathUsesIndexes(t *testing.T) {
	s, _ := newTestStore(t)
	for _, q := range []string{
		`SELECT mac FROM devices WHERE mac = 'x'`,
		`SELECT mac FROM devices WHERE ` + byIP,
		`SELECT id FROM conflicts WHERE (mac = 'x' OR (claimant = 'x' AND claimant != '')) AND last_seen >= ''`,
	} {
		rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+q, "192.168.1.1")
		if err != nil {
			rows, err = s.db.Query(`EXPLAIN QUERY PLAN ` + q)
		}
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		joined := strings.Join(plan, "; ")
		if strings.Contains(joined, "SCAN devices") || strings.Contains(joined, "SCAN conflicts") {
			t.Errorf("%s: full scan: %s", q, joined)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.Observe(arpSeen("00:11:22:33:44:01", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen should succeed: %v", err)
	}
	defer s2.Close()
	if n := s2.Count(); n != 1 {
		t.Errorf("data should survive reopen, Count() = %d", n)
	}
}

// TestMigrationCleansV1Data opens a database written by the v1 code with
// what it let in: several rows on one address, a key that is not a MAC
// (DHCP hlen 16), raw control bytes in a hostname.
func TestMigrationCleansV1Data(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE devices (mac TEXT PRIMARY KEY, ip TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL DEFAULT '', vendor_class TEXT NOT NULL DEFAULT '', vendor TEXT NOT NULL DEFAULT '',
			os TEXT NOT NULL DEFAULT '', device_type TEXT NOT NULL DEFAULT '', stable_id TEXT NOT NULL DEFAULT '',
			labels TEXT NOT NULL DEFAULT '[]', randomized_mac INTEGER NOT NULL DEFAULT 0,
			first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)`,
		`CREATE INDEX idx_ip ON devices(ip) WHERE ip != ''`,
		`INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, stable_id) VALUES
			('b8:27:eb:00:00:01', '192.168.1.50', 'old-holder', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'abc'),
			('00:11:22:00:00:02', '192.168.1.50', 'new-holder', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z', ''),
			('aa:bb:cc:dd:ee:ff:01:02:03:04:05:06:07:08:09:0a', '', 'x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', ''),
			('02:00:00:00:00:01', '', 'a' || char(0) || 'b' || char(27) || '[31m', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer s.Close()
	if s.Count() != 3 {
		t.Errorf("Count() = %d, want 3 (the non-MAC key is gone)", s.Count())
	}
	if d := mustGet(t, s, "00:11:22:00:00:02"); d.IP != "192.168.1.50" {
		t.Errorf("most recent holder should keep the address: %+v", d)
	}
	if d := mustGet(t, s, "b8:27:eb:00:00:01"); d.IP != "" {
		t.Errorf("older holder should lose the address: %q", d.IP)
	}
	if d := mustGet(t, s, "02:00:00:00:00:01"); d.Hostname != "ab[31m" {
		t.Errorf("hostname not sanitised: %q", d.Hostname)
	}
	if _, err := s.db.Exec(`UPDATE devices SET ip = '192.168.1.50' WHERE mac = 'b8:27:eb:00:00:01'`); err == nil {
		t.Error("the unique index on ip should exist after migration")
	}
}
