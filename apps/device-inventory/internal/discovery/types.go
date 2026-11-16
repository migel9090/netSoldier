// Package discovery holds the vocabulary shared by the passive listeners and
// the store: where a piece of evidence came from (Source), what a listener
// observed (Sighting), and the normalisation every LAN-learned value goes
// through before it is trusted with a row in the inventory.
package discovery

import "time"

// Source names the protocol (or, later, the system) a piece of evidence came
// from. It is stored next to every field it set, so a stronger source can
// replace what a weaker one said and nothing else can.
type Source string

const (
	// SourceSSDP is the product token of a UPnP SERVER header: a model, not
	// a name, and the weakest evidence the inventory accepts.
	SourceSSDP Source = "ssdp"
	// SourceMDNS is a host's own .local name from an mDNS A record.
	SourceMDNS Source = "mdns"
	// SourceLLDP is an LLDP system name, usually set by an administrator on
	// switches and access points.
	SourceLLDP Source = "lldp"
	// SourceARP is an ARP sender address pair; it carries no name.
	SourceARP Source = "arp"
	// SourceDHCP is a DHCP client message (option 12 name, options 55/60
	// profile, the requested address).
	SourceDHCP Source = "dhcp"
	// SourceLease is reserved for the router's DHCP lease table. It is the
	// only authoritative source: what it says about a binding is applied even
	// when it contradicts a live passive observation. Nothing produces it yet.
	SourceLease Source = "lease"
)

// Rank orders sources by how much their word on a device's name is worth.
// Unknown or empty sources rank 0, below everything.
func (s Source) Rank() int {
	switch s {
	case SourceSSDP:
		return 1
	case SourceMDNS:
		return 2
	case SourceLLDP:
		return 3
	case SourceARP, SourceDHCP:
		return 4
	case SourceLease:
		return 9
	}
	return 0
}

// Authoritative reports whether the source may overrule a live binding.
func (s Source) Authoritative() bool { return s == SourceLease }

// Sighting is one observation from a listener.
//
// MAC is set only for claims the listener could tie to the frame's own
// Ethernet source (ARP sender, DHCP chaddr, LLDP source); a listener that
// cannot make that check leaves it empty. A sighting with a MAC may assert an
// IPv4 binding in IP. A sighting without one (mDNS, SSDP arrive on a UDP
// socket, so the link layer is not visible) can only offer a Name for
// whichever device currently holds IP, the datagram's source address.
type Sighting struct {
	Source      Source
	MAC         string
	IP          string
	Name        string
	Fingerprint string // DHCP option 55, comma-separated codes in request order
	VendorClass string // DHCP option 60

	// Derived locally (OUI table, dhcpfp), never read from the wire.
	Vendor     string
	OS         string
	DeviceType string

	// CapturedAt is when netagent captured the frame (its clock); zero when
	// unknown. Interface is the capture interface it named. Both come from
	// the agent, which is trusted, not from the frame's own bytes. The store
	// records the sighting at CapturedAt when it is set, so last_seen and the
	// ClickHouse event reflect capture time rather than ingestion time.
	CapturedAt time.Time
	Interface  string
}
