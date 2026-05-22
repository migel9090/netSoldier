package pcapreplay

import (
	"fmt"
	"os"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

type Alert struct {
	Domain     string
	ClientIP   string
	MatchedIoC string
	Severity   string
	Source     string
	QueryType  string
}

type Result struct {
	Packets int
	Queries int
	Alerts  []Alert
}

// Replay opens a PCAP file, extracts DNS queries from each packet,
// and matches them against the provided IoC matcher. It returns
// the total packet/query counts and any detection alerts.
func Replay(pcapPath string, matcher *iocmatch.Matcher) (*Result, error) {
	f, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("pcap reader: %w", err)
	}

	lt := reader.LinkType()
	if lt != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("unsupported link type: %v (only Ethernet)", lt)
	}

	result := &Result{}

	for {
		data, _, err := reader.ReadPacketData()
		if err != nil {
			break
		}
		result.Packets++

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}
		dns := dnsLayer.(*layers.DNS)
		if dns.QR {
			continue
		}

		var srcIP string
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			srcIP = ipLayer.(*layers.IPv4).SrcIP.String()
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			srcIP = ipLayer.(*layers.IPv6).SrcIP.String()
		}

		for _, q := range dns.Questions {
			domain := strings.ToLower(strings.TrimSuffix(string(q.Name), "."))
			result.Queries++

			if ioc, ok := matcher.MatchDomain(domain); ok {
				result.Alerts = append(result.Alerts, Alert{
					Domain:     domain,
					ClientIP:   srcIP,
					MatchedIoC: ioc.Value,
					Severity:   iocmatch.DeriveSeverity(ioc),
					Source:     ioc.Source,
					QueryType:  q.Type.String(),
				})
			}
		}
	}

	return result, nil
}
