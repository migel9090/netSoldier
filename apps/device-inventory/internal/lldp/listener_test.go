package lldp

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

var src = net.HardwareAddr{0x00, 0x11, 0x24, 0x00, 0x00, 0x07}

func tlv(typ int, v []byte) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(typ<<9|len(v)))
	return append(b, v...)
}

func lldpFrame(eth net.HardwareAddr, body ...[]byte) []byte {
	f := []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	f = append(f, eth...)
	f = append(f, 0x88, 0xcc)
	for _, b := range body {
		f = append(f, b...)
	}
	return f
}

func standard(name string) []byte {
	var b []byte
	b = append(b, tlv(1, append([]byte{4}, src...))...)
	b = append(b, tlv(2, []byte("\x05eth0"))...)
	b = append(b, tlv(3, []byte{0, 120})...)
	b = append(b, tlv(tlvSysName, []byte(name))...)
	b = append(b, tlv(8, []byte{5, 1, 192, 168, 1, 77, 2, 0, 0, 0, 1, 0})...)
	return append(b, tlv(0, nil)...)
}

func TestParseFrame(t *testing.T) {
	s, err := ParseFrame(lldpFrame(src, standard("core-switch")))
	if err != nil {
		t.Fatal(err)
	}
	// Name only: the management address is not a binding for this MAC.
	if s != (discovery.Sighting{Source: discovery.SourceLLDP, MAC: "00:11:24:00:00:07", Name: "core-switch"}) {
		t.Errorf("got %+v", s)
	}
}

func TestParseFrameRefuses(t *testing.T) {
	group := net.HardwareAddr{0x01, 0x80, 0xc2, 0, 0, 0x0e}
	wrongType := lldpFrame(src, standard("x"))
	wrongType[13] = 0
	cases := map[string]struct {
		f    []byte
		want error
	}{
		"header only":     {lldpFrame(src), discovery.ErrMalformed},
		"no system name":  {lldpFrame(src, tlv(1, []byte{4, 1, 2, 3, 4, 5, 6}), tlv(0, nil)), discovery.ErrIgnored},
		"control-only":    {lldpFrame(src, tlv(tlvSysName, []byte("\x00\x1b\x07"))), discovery.ErrIgnored},
		"group source":    {lldpFrame(group, standard("x")), discovery.ErrMalformed},
		"not lldp":        {wrongType, discovery.ErrIgnored},
		"truncated value": {lldpFrame(src, tlv(tlvSysName, []byte("name"))[:4]), discovery.ErrIgnored},
	}
	for name, c := range cases {
		if _, err := ParseFrame(c.f); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	s, err := ParseFrame(lldpFrame(src, tlv(tlvSysName, []byte("sw\x1b[1m\u202eitch"))))
	if err != nil || s.Name != "sw[1mitch" {
		t.Errorf("sanitised name: %+v %v", s, err)
	}
}

func FuzzParseLLDP(f *testing.F) {
	f.Add(lldpFrame(src, standard("sw1")))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseFrame(b)
		if err == nil && (s.MAC != net.HardwareAddr(b[6:12]).String() || len(s.Name) > discovery.MaxNameLen) {
			t.Fatalf("bad sighting %+v", s)
		}
		_ = parseSysName(b)
	})
}
