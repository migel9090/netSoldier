// Package store keeps the device inventory in SQLite and enforces its
// identity model.
//
// # Identity model
//
// A row is one link-layer address (MAC). The MAC is the row's key and is
// never rewritten, so nothing a device says can move another device's labels
// or history onto itself. Every value a row holds records the source that set
// it (dhcp, arp, lldp, mdns, ssdp, and later the router's lease table), and a
// value is replaced only by evidence from a stronger source, or by evidence
// of the same strength while the device is still new. A claim that names a
// MAC is only accepted from a frame whose Ethernet source is that MAC (the
// listeners enforce this); mDNS and SSDP arrive without a visible link layer
// and can only offer a name to whichever device currently holds their source
// address. An address has at most one holder and a device holds at most one
// address. A binding is live once it has been seen at least twice and its
// holder keeps re-confirming it within BINDING_TTL. A claim that contradicts
// a live binding (another MAC claiming the address, or the holder claiming a
// different one) is a conflict: it is recorded in the conflicts table,
// counted in device_inventory_conflicts_total, logged, and shown on both
// devices in the API, and it is not applied. When a binding lapses, the next
// claim takes the address over; that is a rebind, also counted and logged. A
// device is established once it carries labels or has been seen across 24 h.
// An established device does not accept a same-strength change of name or
// DHCP profile either; that is recorded as a conflict. MAC rotation is
// modelled as a link (rotation_of points at the row the device probably used
// before), never as a re-key, and labels never move between rows.
//
// # Provenance
//
// Sources rank ssdp < mdns < lldp < dhcp/arp < lease (discovery.Source).
// SourceLease is reserved for the router's DHCP lease table and is the only
// authoritative source: it may overrule a live binding. Nothing produces it
// yet; when something does, its claims go through Observe like any other.
//
// # What this does not protect against
//
// Passive observation authenticates nothing. A host that forges its Ethernet
// source address (any machine an attacker has root on) can speak for any
// MAC; the link-layer check only stops cheap forgeries such as a DHCP
// message from an ordinary UDP socket or an ARP packet speaking for another
// MAC. Against a full forger the guarantees are temporal: a live binding
// cannot be taken while its holder keeps confirming it, and an established
// device's name and profile cannot be rewritten by an equal source. Once the
// real device has been silent at layer 2 for longer than BINDING_TTL
// (switched off, or simply quiet; enable the ARP scanner so active devices
// re-confirm), its address can be taken, and its MAC can be bound to a new
// address, and the inventory cannot tell that from a device that moved. A
// device that really uses two addresses keeps the first; the second shows up
// as a conflict. mDNS and SSDP names can be put on any address by spoofing a
// UDP source address, but only where nothing stronger has named the device.
// While a flood of new MACs is under way, genuinely new devices are not
// admitted either (known devices keep updating). Only an authoritative
// source closes these gaps.
//
// # Growth
//
// The table is capped (DEVICE_MAX_ROWS). A new device beyond the cap evicts
// the least valuable row: never a labelled one, non-established before
// established, rows without a live binding first, oldest sighting first.
// Sightings are rate-limited per source (MAC, or address for mDNS/SSDP),
// identical repeats within a few seconds are coalesced without a write, and
// new rows have their own global rate. The row count is kept in memory, so
// no sighting runs a full count.
package store
