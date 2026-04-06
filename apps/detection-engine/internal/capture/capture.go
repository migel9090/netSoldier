package capture

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
)

var packetsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "capture",
	Name:      "packets_total",
	Help:      "Total packets captured from SPAN interface.",
})

func init() {
	prometheus.MustRegister(packetsTotal)
}

// Capturer reads packets from a SPAN interface via AF_PACKET and
// extracts bidirectional network flows.
type Capturer struct {
	iface       string
	flowCh      chan<- FlowRecord
	idleTimeout time.Duration
}

// New creates a packet capturer for the given network interface.
// Completed flows (idle > idleTimeout) are sent to flowCh.
func New(iface string, flowCh chan<- FlowRecord, idleTimeout time.Duration) *Capturer {
	return &Capturer{
		iface:       iface,
		flowCh:      flowCh,
		idleTimeout: idleTimeout,
	}
}

// Run captures packets until the context is cancelled. Requires CAP_NET_RAW.
func (c *Capturer) Run(ctx context.Context) error {
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(c.iface),
		afpacket.OptBlockTimeout(2*time.Second),
		afpacket.SocketRaw,
		afpacket.TPacketVersion3,
	)
	if err != nil {
		return fmt.Errorf("af_packet %s: %w", c.iface, err)
	}
	defer handle.Close()

	tracker := newTracker(c.flowCh)
	go tracker.sweeper(ctx, c.idleTimeout)

	slog.Info("capture started", "interface", c.iface, "idle_timeout", c.idleTimeout)

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ip4, &ip6, &tcp, &udp)
	parser.IgnoreUnsupported = true
	var decoded []gopacket.LayerType

	for {
		select {
		case <-ctx.Done():
			tracker.flushAll()
			return nil
		default:
		}

		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			continue
		}

		_ = parser.DecodeLayers(data, &decoded)

		var srcIP, dstIP net.IP
		var protocol uint8
		var srcPort, dstPort uint16
		var tcpFlags uint8
		var vlanID uint16
		hasIP := false

		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP
				dstIP = ip4.DstIP
				protocol = uint8(ip4.Protocol)
				hasIP = true
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP
				dstIP = ip6.DstIP
				protocol = uint8(ip6.NextHeader)
				hasIP = true
			case layers.LayerTypeTCP:
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
				if tcp.SYN {
					tcpFlags |= 0x02
				}
				if tcp.ACK {
					tcpFlags |= 0x10
				}
				if tcp.FIN {
					tcpFlags |= 0x01
				}
				if tcp.RST {
					tcpFlags |= 0x04
				}
				if tcp.PSH {
					tcpFlags |= 0x08
				}
			case layers.LayerTypeUDP:
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			case layers.LayerTypeDot1Q:
				vlanID = dot1q.VLANIdentifier
			}
		}

		if !hasIP {
			continue
		}

		packetsTotal.Inc()
		tracker.update(srcIP, dstIP, srcPort, dstPort, protocol, uint64(len(data)), tcpFlags, vlanID)
	}
}
