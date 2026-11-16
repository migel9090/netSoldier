package capture

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

// run assembles p and runs it against pkt in the reference BPF VM, returning
// the accepted byte count (0 = dropped). The VM applies the kernel's rule
// that an out-of-bounds load drops the packet.
func run(t *testing.T, p []bpf.Instruction, pkt []byte) int {
	t.Helper()
	vm, err := bpf.NewVM(p)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	n, err := vm.Run(pkt)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return n
}

// ethFrame builds an Ethernet frame of etherType with payload.
func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14)
	binary.BigEndian.PutUint16(f[12:14], etherType)
	return append(f, payload...)
}

// udp4 builds an IPv4/UDP datagram to dst:dstPort, with optional extra IP
// header words (ihlWords beyond the minimum 5) and a fragment flag.
func udp4(dst net.IP, dstPort uint16, ihlWords int, fragOffset uint16, body []byte) []byte {
	ihl := 20 + 4*ihlWords
	ip := make([]byte, ihl+8+len(body))
	ip[0] = byte(0x40 | (ihl / 4))
	ip[9] = 17 // UDP
	binary.BigEndian.PutUint16(ip[6:8], fragOffset)
	copy(ip[16:20], dst.To4())
	udp := ip[ihl:]
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	copy(udp[8:], body)
	return ethFrame(etherIPv4, ip)
}

func TestARPFilter(t *testing.T) {
	p, _ := Lookup("arp")
	if run(t, p.Filter, ethFrame(etherARP, make([]byte, 28))) == 0 {
		t.Error("ARP frame dropped")
	}
	if run(t, p.Filter, ethFrame(etherIPv4, make([]byte, 28))) != 0 {
		t.Error("non-ARP frame accepted")
	}
	if run(t, p.Filter, make([]byte, 8)) != 0 {
		t.Error("runt frame accepted")
	}
}

func TestDHCPFilter(t *testing.T) {
	p, _ := Lookup("dhcp")
	body := make([]byte, 240)
	cases := map[string]struct {
		pkt    []byte
		accept bool
	}{
		"dhcp to 67":      {udp4(net.IPv4bcast, 67, 0, 0, body), true},
		"ip options":      {udp4(net.IPv4bcast, 67, 1, 0, body), true},
		"to 68":           {udp4(net.IPv4bcast, 68, 0, 0, body), false},
		"later fragment":  {udp4(net.IPv4bcast, 67, 0, 0x0010, body), false},
		"tcp":             {func() []byte { f := udp4(net.IPv4bcast, 67, 0, 0, body); f[14+9] = 6; return f }(), false},
		"arp":             {ethFrame(etherARP, make([]byte, 28)), false},
		"truncated frame": {make([]byte, 20), false},
	}
	for name, c := range cases {
		if got := run(t, p.Filter, c.pkt) != 0; got != c.accept {
			t.Errorf("%s: accept=%v, want %v", name, got, c.accept)
		}
	}
}

func TestMulticastFilters(t *testing.T) {
	mdns, _ := Lookup("mdns")
	if run(t, mdns.Filter, udp4(net.IPv4(224, 0, 0, 251), 5353, 0, 0, make([]byte, 20))) == 0 {
		t.Error("mDNS to its group dropped")
	}
	// A datagram to 5353 but a different destination must be dropped: it is
	// not the multicast we joined.
	if run(t, mdns.Filter, udp4(net.IPv4(10, 0, 0, 1), 5353, 0, 0, make([]byte, 20))) != 0 {
		t.Error("mDNS to a non-group address accepted")
	}
	ssdp, _ := Lookup("ssdp")
	if run(t, ssdp.Filter, udp4(net.IPv4(239, 255, 255, 250), 1900, 0, 0, make([]byte, 20))) == 0 {
		t.Error("SSDP to its group dropped")
	}
	if run(t, ssdp.Filter, udp4(net.IPv4(239, 255, 255, 250), 1901, 0, 0, make([]byte, 20))) != 0 {
		t.Error("SSDP to the wrong port accepted")
	}
}

func TestLLDPFilter(t *testing.T) {
	p, _ := Lookup("lldp")
	if run(t, p.Filter, ethFrame(etherLLDP, make([]byte, 10))) == 0 {
		t.Error("LLDP dropped")
	}
	if run(t, p.Filter, ethFrame(etherIPv4, make([]byte, 10))) != 0 {
		t.Error("non-LLDP accepted")
	}
}

// FuzzFilters feeds arbitrary bytes through every protocol's filter in the
// reference VM: a filter must never panic or error, whatever the input.
func FuzzFilters(f *testing.F) {
	f.Add(ethFrame(etherARP, make([]byte, 28)))
	f.Add(udp4(net.IPv4(224, 0, 0, 251), 5353, 0, 0, make([]byte, 20)))
	f.Add([]byte{0x08, 0x00})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		for _, p := range Protocols {
			vm, err := bpf.NewVM(p.Filter)
			if err != nil {
				t.Fatalf("%s filter does not assemble: %v", p.Name, err)
			}
			if _, err := vm.Run(pkt); err != nil {
				t.Fatalf("%s filter errored on %d bytes: %v", p.Name, len(pkt), err)
			}
		}
	})
}
