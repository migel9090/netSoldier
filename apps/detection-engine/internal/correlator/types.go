package correlator

// ConnectionRecord is an enriched "who → where → what" record written
// to ClickHouse after correlating flow, DNS, and device inventory data.
type ConnectionRecord struct {
	Timestamp     string `json:"timestamp"`
	SrcMAC        string `json:"src_mac"`
	SrcHostname   string `json:"src_hostname"`
	SrcVendor     string `json:"src_vendor"`
	SrcOS         string `json:"src_os"`
	SrcDeviceType string `json:"src_device_type"`
	SrcIP         string `json:"src_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstIP         string `json:"dst_ip"`
	DstDomain     string `json:"dst_domain"`
	DstPort       uint16 `json:"dst_port"`
	Protocol      uint8  `json:"protocol"`
	BytesIn       uint64 `json:"bytes_in"`
	BytesOut      uint64 `json:"bytes_out"`
	PacketsIn     uint32 `json:"packets_in"`
	PacketsOut    uint32 `json:"packets_out"`
	DurationMs    uint32 `json:"duration_ms"`
	TCPFlags      uint8  `json:"tcp_flags"`
	VlanID        uint16 `json:"vlan_id"`
}

// DeviceInfo holds cached device inventory data for IP-to-device resolution.
type DeviceInfo struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	Vendor     string `json:"vendor"`
	OS         string `json:"os"`
	DeviceType string `json:"device_type"`
}
