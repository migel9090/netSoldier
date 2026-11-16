package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

func conflictKinds(cs []Conflict) map[string]Conflict {
	m := map[string]Conflict{}
	for _, c := range cs {
		m[c.Kind] = c
	}
	return m
}

// DI-2, from the auditor's TestAuditForgedChaddrRewritesVictim: one DHCP
// message carrying the router's MAC used to rewrite the router's address,
// name and OS while keeping its labels. The listener now refuses a chaddr
// that is not the Ethernet source; this is the store's half for a forger who
// fakes the Ethernet source too.
func TestForgedClaimCannotRewriteLabelledRouter(t *testing.T) {
	s, c := newTestStore(t)
	router := "00:11:24:aa:bb:01"
	observe(t, s, dhcpSeen(router, "192.168.1.1", "gateway", "1,3,6", "udhcp 1.36"))
	confirm(t, s, c, router, "192.168.1.1")
	if _, err := s.SetLabels(router, []string{"critical", "gateway"}); err != nil {
		t.Fatal(err)
	}

	c.advance(time.Minute)
	res := observe(t, s, dhcpSeen(router, "192.168.1.66", "kids-tablet", "1,3,6,15,26,28,51,58,59,43", "android-dhcp-14"))

	d := mustGet(t, s, router)
	if d.IP != "192.168.1.1" || d.Hostname != "gateway" || d.VendorClass != "udhcp 1.36" || len(d.Labels) != 2 {
		t.Fatalf("one forged datagram rewrote the router: %+v", d)
	}
	got := conflictKinds(res.Conflicts)
	for _, k := range []string{"ip_moved", "name", "profile"} {
		if _, ok := got[k]; !ok {
			t.Errorf("expected a %s conflict, got %+v", k, res.Conflicts)
		}
	}
	if got["ip_moved"].IP != "192.168.1.1" || got["ip_moved"].Value != "192.168.1.66" {
		t.Errorf("ip_moved conflict: %+v", got["ip_moved"])
	}
	if d.ConflictCount != 3 || len(d.Conflicts) != 3 {
		t.Errorf("conflicts must be surfaced on the device: %+v", d.Conflicts)
	}
}

// DI-2/DI-8: another MAC claiming a live address is a conflict on the
// holder, and by-IP resolution keeps answering with the holder.
func TestLiveBindingCannotBeTaken(t *testing.T) {
	s, c := newTestStore(t)
	router, attacker := "00:11:24:aa:bb:01", "02:de:ad:be:ef:01"
	confirm(t, s, c, router, "192.168.77.1")

	res := observe(t, s, arpSeen(attacker, "192.168.77.1"))
	if len(res.Conflicts) != 1 || res.Conflicts[0].Kind != "ip_taken" ||
		res.Conflicts[0].MAC != router || res.Conflicts[0].Claimant != attacker || !res.Conflicts[0].New {
		t.Fatalf("expected one new ip_taken conflict, got %+v", res.Conflicts)
	}
	if res.Device.MAC != attacker || res.Device.IP != "" {
		t.Errorf("the claimant exists but holds nothing: %+v", res.Device)
	}

	holder, err := s.GetByIP("192.168.77.1")
	if err != nil {
		t.Fatal(err)
	}
	if holder == nil || holder.MAC != router {
		t.Fatalf("by-ip must still resolve to the router, got %+v", holder)
	}
	if holder.ConflictCount != 1 {
		t.Errorf("the conflict must show on the holder: %+v", holder.Conflicts)
	}
	if a := mustGet(t, s, attacker); a.ConflictCount != 1 {
		t.Errorf("the conflict must show on the claimant: %+v", a.Conflicts)
	}

	// Repeats bump the record rather than adding rows.
	c.advance(20 * time.Second)
	res = observe(t, s, arpSeen(attacker, "192.168.77.1"))
	if len(res.Conflicts) != 1 || res.Conflicts[0].New || res.Conflicts[0].Count != 2 {
		t.Errorf("repeat should bump the conflict: %+v", res.Conflicts)
	}
}

// DI-8, from the auditor's TestAuditDuplicateIP and
// TestAuditTopologyStaleIPWins: after a lease moved, two rows held the
// address and lookups picked the stale one. A lapsed binding is now taken
// over and the old holder loses the address.
func TestLapsedBindingIsTakenOver(t *testing.T) {
	s, c := newTestStore(t)
	old, next := "b8:27:eb:00:00:01", "00:11:22:00:00:02"
	confirm(t, s, c, old, "192.168.1.50")

	c.advance(2 * time.Hour) // longer than BINDING_TTL
	if d, _ := s.GetByIP("192.168.1.50"); d != nil {
		t.Errorf("a lapsed binding is not a current holder: %+v", d)
	}
	res := observe(t, s, arpSeen(next, "192.168.1.50"))
	if res.Rebind == nil || res.Rebind.FromMAC != old || res.Rebind.ToMAC != next {
		t.Fatalf("expected a rebind from %s to %s: %+v", old, next, res.Rebind)
	}
	if res.Released == nil || res.Released.IP != "" {
		t.Errorf("previous holder must be released: %+v", res.Released)
	}
	if d, _ := s.GetByIP("192.168.1.50"); d == nil || d.MAC != next {
		t.Fatalf("by-ip should resolve to the new holder, got %+v", d)
	}
	if d := mustGet(t, s, old); d.IP != "" {
		t.Errorf("old holder still claims the address: %q", d.IP)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM devices WHERE ip = '192.168.1.50'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("rows holding the address = %d (%v), want 1", n, err)
	}
}

// A device that is told "no" (DHCPNAK) and requests another address right
// away moves without a conflict: a binding seen once is only tentative.
func TestTentativeBindingCanBeCorrected(t *testing.T) {
	s, c := newTestStore(t)
	mac := "02:00:00:00:00:10"
	observe(t, s, dhcpSeen(mac, "10.0.0.5", "laptop", "", ""))
	c.advance(2 * time.Second)
	res := observe(t, s, dhcpSeen(mac, "192.168.1.30", "laptop", "", ""))
	if len(res.Conflicts) != 0 || res.Device.IP != "192.168.1.30" {
		t.Fatalf("tentative binding should move: %+v %+v", res.Device, res.Conflicts)
	}

	// Once live, the same move is a conflict.
	confirm(t, s, c, mac, "192.168.1.30")
	c.advance(time.Minute)
	res = observe(t, s, dhcpSeen(mac, "192.168.1.31", "laptop", "", ""))
	if len(res.Conflicts) != 1 || res.Conflicts[0].Kind != "ip_moved" || res.Device.IP != "192.168.1.30" {
		t.Fatalf("live binding must not move: %+v %+v", res.Device, res.Conflicts)
	}
}

// The router's lease table (not wired in yet) is the one source that may
// overrule a live binding.
func TestAuthoritativeSourceOverridesLiveBinding(t *testing.T) {
	s, c := newTestStore(t)
	a, b := "00:11:22:00:00:01", "00:11:22:00:00:02"
	confirm(t, s, c, a, "192.168.1.40")
	res := observe(t, s, discovery.Sighting{Source: discovery.SourceLease, MAC: b, IP: "192.168.1.40", Name: "lease-name"})
	if len(res.Conflicts) != 0 || res.Rebind == nil || res.Device.IP != "192.168.1.40" {
		t.Fatalf("lease should rebind: %+v", res)
	}
	if res.Device.HostnameSource != "lease" {
		t.Errorf("hostname source = %q", res.Device.HostnameSource)
	}
}

// DI-3, from the auditor's TestAuditTwoPhonesCollapse: two Android phones
// with the same vendor class and no hostname collapsed into one row, and the
// label moved to the second phone.
func TestTwoPhonesWithSameVendorClassStayApart(t *testing.T) {
	s, c := newTestStore(t)
	fp := "1,3,6,15,26,28,51,58,59,43"
	a, b := "da:a1:19:00:00:01", "f2:6e:0b:00:00:02"
	observe(t, s, dhcpSeen(a, "192.168.1.20", "", fp, "android-dhcp-14"))
	if _, err := s.SetLabels(a, []string{"kid-phone"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	observe(t, s, dhcpSeen(b, "192.168.1.21", "", fp, "android-dhcp-14"))

	if s.Count() != 2 {
		t.Fatalf("Count() = %d, want two separate phones", s.Count())
	}
	if d := mustGet(t, s, a); len(d.Labels) != 1 || d.IP != "192.168.1.20" {
		t.Errorf("phone A changed: %+v", d)
	}
	if d := mustGet(t, s, b); len(d.Labels) != 0 || d.RotationOf != "" {
		t.Errorf("phone B must not inherit A's label or be linked without a hostname: %+v", d)
	}
}

// DI-3, from the auditor's TestAuditStableIDTakeoverOfRandomizedVictim: a
// device copying a privacy-MAC victim's options 60 and 12 took over the
// victim's row, labels and first-seen included.
func TestCopiedDHCPOptionsCannotTakeOverVictim(t *testing.T) {
	s, c := newTestStore(t)
	victim, attacker := "d6:10:22:33:44:55", "02:de:ad:be:ef:01"
	observe(t, s, dhcpSeen(victim, "192.168.1.10", "Dads-iPhone", "1,121,3,6,15,119,252", "iPhone"))
	confirm(t, s, c, victim, "192.168.1.10")
	if _, err := s.SetLabels(victim, []string{"critical", "trusted"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	observe(t, s, dhcpSeen(attacker, "192.168.1.99", "Dads-iPhone", "", "iPhone"))

	v := mustGet(t, s, victim)
	if v.IP != "192.168.1.10" || len(v.Labels) != 2 {
		t.Errorf("victim record changed: %+v", v)
	}
	a := mustGet(t, s, attacker)
	if len(a.Labels) != 0 || !a.FirstSeen.After(v.FirstSeen) {
		t.Errorf("attacker inherited the victim's labels or history: %+v", a)
	}
}

// From the auditor's TestAuditStableIDUniqueCollision: the stable_id re-key
// could collide with an existing row and fail every later DHCP message for
// that MAC with a UNIQUE error.
func TestRepeatedDHCPForKnownMACNeverFails(t *testing.T) {
	s, c := newTestStore(t)
	a, b := "da:a1:19:00:00:01", "f2:6e:0b:00:00:02"
	observe(t, s, dhcpSeen(a, "192.168.1.20", "pixel", "1,3,6", "android-dhcp-14"))
	c.advance(time.Minute)
	observe(t, s, arpSeen(b, "192.168.1.21"))
	for i := 0; i < 3; i++ {
		c.advance(20 * time.Second)
		if res := observe(t, s, dhcpSeen(b, "192.168.1.21", "pixel", "1,3,6", "android-dhcp-14")); res.Outcome != Applied {
			t.Fatalf("DHCP #%d for %s: %s", i+1, b, res.Outcome)
		}
	}
	if s.Count() != 2 {
		t.Errorf("Count() = %d, want 2", s.Count())
	}
}

// MAC rotation is a link, not a re-key: the old row and its labels stay
// where they are, the new row points at it.
func TestRotationIsALinkNotARekey(t *testing.T) {
	s, c := newTestStore(t)
	first, second := "aa:bb:cc:00:00:01", "ae:bb:cc:00:00:02"
	observe(t, s, dhcpSeen(first, "192.168.1.20", "iphone", "1,3,6", "iPhone"))
	if _, err := s.SetLabels(first, []string{"dad"}); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Hour)
	res := observe(t, s, dhcpSeen(second, "192.168.1.21", "iphone", "1,3,6", "iPhone"))
	if res.Linked != first {
		t.Fatalf("expected a rotation link to %s, got %q", first, res.Linked)
	}
	if s.Count() != 2 {
		t.Fatalf("rotation must not merge rows, Count() = %d", s.Count())
	}
	if d := mustGet(t, s, second); d.RotationOf != first || len(d.Labels) != 0 {
		t.Errorf("new row: %+v", d)
	}
	if d := mustGet(t, s, first); len(d.Labels) != 1 {
		t.Errorf("labels must stay on the old row: %+v", d)
	}
}

// A shared hostname alone never links rows, and neither does a candidate
// that is still active (seen after the new MAC appeared).
func TestRotationLinkNeedsVendorClassAndAQuietPredecessor(t *testing.T) {
	s, c := newTestStore(t)
	observe(t, s, dhcpSeen("aa:bb:cc:00:00:01", "", "shared-name", "", ""))
	c.advance(time.Minute)
	if res := observe(t, s, dhcpSeen("ae:bb:cc:00:00:02", "", "shared-name", "", "")); res.Linked != "" {
		t.Errorf("hostname-only rows linked: %q", res.Linked)
	}

	observe(t, s, arpSeen("aa:bb:cc:00:00:03", ""))
	c.advance(time.Second)
	observe(t, s, dhcpSeen("aa:bb:cc:00:00:04", "", "tablet", "", "vc"))
	c.advance(time.Second)
	observe(t, s, dhcpSeen("aa:bb:cc:00:00:03", "", "tablet", "", "vc")) // 03 seen after 04 appeared
	if d := mustGet(t, s, "aa:bb:cc:00:00:03"); d.RotationOf != "" {
		t.Errorf("concurrently active devices linked: %+v", d)
	}
}

// From the auditor's TestAuditEnrichByIP and the old
// TestEnrichByIPCannotRenameDevice: a by-IP name (mDNS/SSDP) cannot rename a
// device a stronger source named, cannot touch a lapsed binding, and never
// keeps a stale row alive.
func TestNamesByAddress(t *testing.T) {
	s, c := newTestStore(t)
	router := "00:11:22:33:44:01"
	observe(t, s, dhcpSeen(router, "192.168.1.1", "router", "", ""))
	c.advance(20 * time.Second)

	res := observe(t, s, discovery.Sighting{Source: discovery.SourceMDNS, IP: "192.168.1.1", Name: "definitely-not-the-router"})
	if res.Outcome != Applied || len(res.Conflicts) != 0 {
		t.Fatalf("weaker source should be ignored quietly: %+v", res)
	}
	if d := mustGet(t, s, router); d.Hostname != "router" {
		t.Errorf("hostname overwritten by mDNS: %q", d.Hostname)
	}

	printer := "00:11:22:33:44:02"
	observe(t, s, arpSeen(printer, "192.168.1.30"))
	observe(t, s, discovery.Sighting{Source: discovery.SourceSSDP, IP: "192.168.1.30", Name: "MiniDLNA"})
	observe(t, s, discovery.Sighting{Source: discovery.SourceMDNS, IP: "192.168.1.30", Name: "printer"})
	d := mustGet(t, s, printer)
	if d.Hostname != "printer" || d.HostnameSource != "mdns" {
		t.Errorf("mDNS should replace the SSDP product: %+v", d)
	}
	lastSeen := d.LastSeen

	c.advance(2 * time.Hour)
	res = observe(t, s, discovery.Sighting{Source: discovery.SourceMDNS, IP: "192.168.1.30", Name: "spoofed"})
	if res.Outcome != Unbound {
		t.Errorf("a name for a lapsed binding must not apply: %s", res.Outcome)
	}
	if d := mustGet(t, s, printer); !d.LastSeen.Equal(lastSeen) || d.Hostname != "printer" {
		t.Errorf("by-IP sighting changed the device: %+v", d)
	}
	if res := observe(t, s, discovery.Sighting{Source: discovery.SourceMDNS, IP: "192.168.1.99", Name: "x"}); res.Outcome != Unbound {
		t.Errorf("a name for an unknown address: %s", res.Outcome)
	}
}

// An established device does not accept an equal-strength rename or a new
// DHCP profile; a new device does.
func TestEstablishedDevicesAreSticky(t *testing.T) {
	s, c := newTestStore(t)
	mac := "00:11:22:33:44:05"
	observe(t, s, dhcpSeen(mac, "", "first-name", "1,3,6", "MSFT 5.0"))
	c.advance(time.Minute)
	res := observe(t, s, dhcpSeen(mac, "", "second-name", "1,3,6,15", "MSFT 5.0"))
	if !res.Changed || res.Device.Hostname != "second-name" || res.Device.Fingerprint != "1,3,6,15" {
		t.Fatalf("a new device may still be corrected: %+v", res.Device)
	}

	c.advance(25 * time.Hour)
	observe(t, s, arpSeen(mac, ""))
	if d := mustGet(t, s, mac); !d.Established {
		t.Fatalf("seen across 25h should be established: %+v", d)
	}
	c.advance(time.Minute)
	res = observe(t, s, dhcpSeen(mac, "", "renamed", "1,121,3,6", "android-dhcp-14"))
	d := mustGet(t, s, mac)
	if d.Hostname != "second-name" || d.Fingerprint != "1,3,6,15" || d.VendorClass != "MSFT 5.0" {
		t.Errorf("established device rewritten: %+v", d)
	}
	if got := conflictKinds(res.Conflicts); len(got) != 2 || got["name"].Value != "renamed" {
		t.Errorf("expected name and profile conflicts: %+v", res.Conflicts)
	}
	// A stronger source still wins.
	observe(t, s, discovery.Sighting{Source: discovery.SourceLease, MAC: mac, Name: "from-lease"})
	if d := mustGet(t, s, mac); d.Hostname != "from-lease" {
		t.Errorf("stronger source should rename: %q", d.Hostname)
	}
}

func TestCoalescingAndPerSourceRate(t *testing.T) {
	s, c := newTestStore(t)
	mac := "00:11:22:33:44:06"
	observe(t, s, arpSeen(mac, "192.168.1.6"))
	if res := observe(t, s, arpSeen(mac, "192.168.1.6")); res.Outcome != Coalesced {
		t.Errorf("identical repeat: %s, want coalesced", res.Outcome)
	}
	c.advance(20 * time.Second)
	if res := observe(t, s, arpSeen(mac, "192.168.1.6")); res.Outcome != Applied {
		t.Errorf("repeat after the window: %s", res.Outcome)
	}

	// One source cycling through claims is rate-limited.
	limited := 0
	for i := 0; i < 100; i++ {
		res := observe(t, s, arpSeen(mac, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)))
		if res.Outcome == RateLimited {
			limited++
		}
	}
	if limited < 70 {
		t.Errorf("only %d of 100 rapid claims were rate-limited", limited)
	}
}

// DI-7, from the auditor's TestAuditFloodCost: forged sightings grew the
// table without bound and pushed real devices out of GET /devices.
func TestFloodIsBoundedAndKeepsRealDevices(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) {
		o.MaxDevices = 100
		o.NewDeviceRate = 1e6
		o.NewDeviceBurst = 1e6
	})
	nas := "b8:27:eb:aa:aa:aa"
	observe(t, s, dhcpSeen(nas, "192.168.1.2", "real-nas", "", ""))
	if _, err := s.SetLabels(nas, []string{"nas"}); err != nil {
		t.Fatal(err)
	}
	tv := "00:11:22:aa:aa:ab"
	confirm(t, s, c, tv, "192.168.1.3")
	c.advance(25 * time.Hour)
	observe(t, s, arpSeen(tv, "192.168.1.3")) // established, unlabelled
	phone := "da:a1:19:00:00:05"
	confirm(t, s, c, phone, "192.168.1.4") // new today, but its binding is live

	for n := 0; n < 600; n++ {
		mac := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", (n>>32)&0xff, (n>>24)&0xff, (n>>16)&0xff, (n>>8)&0xff, n&0xff)
		if _, err := s.Observe(arpSeen(mac, fmt.Sprintf("10.9.%d.%d", (n/250)%250, n%250+1))); err != nil {
			t.Fatal(err)
		}
		if n%50 == 0 {
			c.advance(time.Second)
		}
	}
	if s.Count() != 100 {
		t.Errorf("Count() = %d, want the cap of 100", s.Count())
	}
	page, err := s.List(3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 3 || page[0].MAC != nas || page[1].MAC != tv || page[2].MAC != phone {
		t.Errorf("first page should be the labelled, the established, then the live device: %+v", page)
	}
}

// With default options, a burst of brand-new MACs is admitted at the
// new-device rate, not at line rate.
func TestNewDeviceRateLimit(t *testing.T) {
	s, _ := newTestStore(t)
	limited := 0
	for n := 0; n < 1000; n++ {
		res := observe(t, s, arpSeen(fmt.Sprintf("02:00:00:00:%02x:%02x", n>>8, n&0xff), ""))
		if res.Outcome == RateLimited {
			limited++
		}
	}
	if s.Count() != 100 || limited != 900 {
		t.Errorf("Count() = %d, limited = %d; want 100 admitted (the burst)", s.Count(), limited)
	}
}

func TestEvictionNeverTakesLabelledDevices(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) { o.MaxDevices = 2 })
	for _, mac := range []string{"00:11:22:33:44:01", "00:11:22:33:44:02"} {
		observe(t, s, arpSeen(mac, ""))
		if _, err := s.SetLabels(mac, []string{"keep"}); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Second)
	}
	res := observe(t, s, arpSeen("00:11:22:33:44:03", ""))
	if res.Outcome != Full || s.Count() != 2 {
		t.Errorf("outcome %s, Count() %d: a full table of labelled devices must refuse, not evict", res.Outcome, s.Count())
	}
}

func TestConflictTableIsCapped(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) { o.MaxConflicts = 64; o.PerSourceBurst = 1e6; o.PerSourceRate = 1e6 })
	router := "00:11:24:aa:bb:01"
	confirm(t, s, c, router, "192.168.1.1")
	for i := 0; i < 300; i++ {
		observe(t, s, arpSeen(router, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1)))
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM conflicts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > 128 {
		t.Errorf("conflicts table holds %d rows, cap is 64 (+ one pruning stride)", n)
	}
	if d := mustGet(t, s, router); len(d.Conflicts) != maxConflictsShown {
		t.Errorf("device shows %d conflicts, want %d", len(d.Conflicts), maxConflictsShown)
	}
}

// GET /devices/{mac} reported conflict_count as the length of the list it
// attaches, which stops at maxConflictsShown, while GET /devices counted
// every recent conflict: one device, two numbers. The count is the total on
// every read; only the attached list is capped.
func TestConflictCountIsTheTotalOnEveryRead(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) { o.PerSourceBurst = 1e6; o.PerSourceRate = 1e6 })
	router := "00:11:24:aa:bb:01"
	confirm(t, s, c, router, "192.168.1.1")
	const claims = maxConflictsShown + 5
	for i := 0; i < claims; i++ {
		observe(t, s, arpSeen(router, fmt.Sprintf("10.1.0.%d", i+1)))
	}

	d := mustGet(t, s, router)
	if len(d.Conflicts) != maxConflictsShown {
		t.Errorf("GetDevice attaches %d conflicts, want the cap of %d", len(d.Conflicts), maxConflictsShown)
	}
	if d.ConflictCount != claims {
		t.Errorf("GetDevice conflict_count = %d, want the total %d", d.ConflictCount, claims)
	}
	byIP, err := s.GetByIP("192.168.1.1")
	if err != nil || byIP == nil {
		t.Fatalf("GetByIP: %+v %v", byIP, err)
	}
	if byIP.ConflictCount != claims {
		t.Errorf("GetByIP conflict_count = %d, want the total %d", byIP.ConflictCount, claims)
	}
	page, err := s.List(10, 0)
	if err != nil || len(page) != 1 {
		t.Fatalf("List: %+v %v", page, err)
	}
	if page[0].ConflictCount != d.ConflictCount {
		t.Errorf("List says %d conflicts, GetDevice %d: the two endpoints disagree",
			page[0].ConflictCount, d.ConflictCount)
	}

	// Outside the window a conflict counts nowhere.
	c.advance(25 * time.Hour)
	if d := mustGet(t, s, router); d.ConflictCount != 0 || len(d.Conflicts) != 0 {
		t.Errorf("after the window: count %d, %d attached", d.ConflictCount, len(d.Conflicts))
	}
}

// One address, one holder, whatever the order of claims.
func TestOneHolderPerAddressInvariant(t *testing.T) {
	s, c := newTestStore(t, func(o *Options) { o.PerSourceBurst = 1e6; o.PerSourceRate = 1e6 })
	macs := []string{"00:11:22:00:00:01", "00:11:22:00:00:02", "00:11:22:00:00:03", "00:11:22:00:00:04"}
	ips := []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"}
	for i := 0; i < 400; i++ {
		observe(t, s, arpSeen(macs[(i*7)%len(macs)], ips[(i*5)%len(ips)]))
		c.advance(time.Duration(i%7) * 11 * time.Minute)
	}
	var dup int
	if err := s.db.QueryRow(`SELECT count(*) FROM (SELECT ip FROM devices WHERE ip != '' GROUP BY ip HAVING count(*) > 1)`).Scan(&dup); err != nil {
		t.Fatal(err)
	}
	if dup != 0 {
		t.Errorf("%d addresses have more than one holder", dup)
	}
}

func TestListPagination(t *testing.T) {
	s, c := newTestStore(t)
	for i := 0; i < 5; i++ {
		observe(t, s, arpSeen(fmt.Sprintf("00:11:22:33:44:%02x", i), ""))
		c.advance(time.Second)
	}
	p1, _ := s.List(2, 0)
	p2, _ := s.List(2, 2)
	p3, _ := s.List(2, 4)
	if len(p1) != 2 || len(p2) != 2 || len(p3) != 1 {
		t.Fatalf("pages: %d %d %d", len(p1), len(p2), len(p3))
	}
	if p1[0].MAC != "00:11:22:33:44:04" || p3[0].MAC != "00:11:22:33:44:00" {
		t.Errorf("most recently seen first: %s ... %s", p1[0].MAC, p3[0].MAC)
	}
	bound, err := s.ListBound()
	if err != nil || len(bound) != 0 {
		t.Errorf("ListBound: %v %v", bound, err)
	}
}
