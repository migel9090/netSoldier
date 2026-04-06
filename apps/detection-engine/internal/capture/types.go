package capture

import "time"

// FlowRecord is an exported network flow (5-tuple + counters).
type FlowRecord struct {
	Timestamp  time.Time
	SrcIP      string
	SrcPort    uint16
	DstIP      string
	DstPort    uint16
	Protocol   uint8
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint32
	PacketsOut uint32
	DurationMs uint32
	TCPFlags   uint8
	VlanID     uint16
}
