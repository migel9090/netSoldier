package discovery

// Info carries a device discovery event from a passive listener.
// MAC may be empty for IP-based protocols (mDNS, SSDP).
type Info struct {
	MAC      string
	IP       string
	Hostname string
	Meta     string // SSDP SERVER header, LLDP system description, etc.
	Protocol string // "mdns", "ssdp", "lldp"
}
