package pcapreplay

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

func buildDNSQuery(srcIP, domain string, txID uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP("1.1.1.1"),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(54000 + txID),
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		ID:     txID,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(domain),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, dns); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type dnsEntry struct {
	srcIP, domain string
}

func generatePCAP(t *testing.T, entries []dnsEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		f.Close()
		t.Fatal(err)
	}

	for i, e := range entries {
		pkt := buildDNSQuery(e.srcIP, e.domain, uint16(i+1))
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Date(2026, 5, 22, 10, 0, i, 0, time.UTC),
			CaptureLength: len(pkt),
			Length:        len(pkt),
		}
		if err := w.WritePacket(ci, pkt); err != nil {
			f.Close()
			t.Fatal(err)
		}
	}

	f.Close()
	return path
}

func TestReplayDNSDetection(t *testing.T) {
	matcher := iocmatch.New()
	matcher.Add([]iocmatch.IoC{
		{Value: "evil.example.com", Type: "domain", Source: "corpus-test", Confidence: 90},
		{Value: "c2.malware.net", Type: "domain", Source: "corpus-test", Confidence: 85},
	})

	pcap := generatePCAP(t, []dnsEntry{
		{"192.168.1.42", "evil.example.com"},
		{"192.168.1.42", "google.com"},
		{"192.168.1.100", "c2.malware.net"},
	})

	result, err := Replay(pcap, matcher)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	if result.Packets != 3 {
		t.Errorf("packets: got %d, want 3", result.Packets)
	}
	if result.Queries != 3 {
		t.Errorf("queries: got %d, want 3", result.Queries)
	}
	if len(result.Alerts) != 2 {
		t.Fatalf("alerts: got %d, want 2", len(result.Alerts))
	}

	if result.Alerts[0].Domain != "evil.example.com" {
		t.Errorf("alert[0].domain: got %q", result.Alerts[0].Domain)
	}
	if result.Alerts[0].ClientIP != "192.168.1.42" {
		t.Errorf("alert[0].client_ip: got %q", result.Alerts[0].ClientIP)
	}
	if result.Alerts[0].Severity != "critical" {
		t.Errorf("alert[0].severity: got %q", result.Alerts[0].Severity)
	}

	if result.Alerts[1].Domain != "c2.malware.net" {
		t.Errorf("alert[1].domain: got %q", result.Alerts[1].Domain)
	}
	if result.Alerts[1].ClientIP != "192.168.1.100" {
		t.Errorf("alert[1].client_ip: got %q", result.Alerts[1].ClientIP)
	}
}

func TestReplayBenignTraffic(t *testing.T) {
	matcher := iocmatch.New()
	matcher.Add([]iocmatch.IoC{
		{Value: "evil.example.com", Type: "domain", Source: "test", Confidence: 90},
	})

	pcap := generatePCAP(t, []dnsEntry{
		{"192.168.1.42", "google.com"},
		{"192.168.1.42", "github.com"},
	})

	result, err := Replay(pcap, matcher)
	if err != nil {
		t.Fatal(err)
	}

	if result.Queries != 2 {
		t.Errorf("queries: got %d, want 2", result.Queries)
	}
	if len(result.Alerts) != 0 {
		t.Errorf("expected 0 alerts for benign traffic, got %d", len(result.Alerts))
	}
}

func TestReplaySubdomainMatch(t *testing.T) {
	matcher := iocmatch.New()
	matcher.Add([]iocmatch.IoC{
		{Value: "evil.com", Type: "domain", Source: "test", Confidence: 80},
	})

	pcap := generatePCAP(t, []dnsEntry{
		{"192.168.1.42", "sub.evil.com"},
	})

	result, err := Replay(pcap, matcher)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Alerts) != 1 {
		t.Fatalf("subdomain should match parent IoC, got %d alerts", len(result.Alerts))
	}
	if result.Alerts[0].MatchedIoC != "evil.com" {
		t.Errorf("matched_ioc: got %q, want evil.com", result.Alerts[0].MatchedIoC)
	}
}

func TestReplayEmptyPCAP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	f.Close()

	result, err := Replay(path, iocmatch.New())
	if err != nil {
		t.Fatal(err)
	}
	if result.Packets != 0 || result.Queries != 0 || len(result.Alerts) != 0 {
		t.Errorf("empty PCAP: packets=%d queries=%d alerts=%d", result.Packets, result.Queries, len(result.Alerts))
	}
}

func TestReplayInvalidPath(t *testing.T) {
	_, err := Replay("/nonexistent/path.pcap", iocmatch.New())
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
