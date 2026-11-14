package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDefaultRouteInterface(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "route")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth1\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n" +
		"wg0\t00000000\t00000000\t0000\t0\t0\t0\t00000000\n" + // default route, not up
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
	if got, err := defaultRouteInterface(write(table)); err != nil || got != "eth0" {
		t.Errorf("got %q %v, want eth0", got, err)
	}
	if _, err := defaultRouteInterface(write("Iface\tDestination\n")); err == nil {
		t.Error("no default route should be an error")
	}
	if _, err := defaultRouteInterface(filepath.Join(dir, "missing")); err == nil {
		t.Error("unreadable table should be an error")
	}
}

func TestResolveInterface(t *testing.T) {
	if _, err := ResolveInterface("does-not-exist0"); err == nil {
		t.Error("unknown interface accepted")
	}
}

func TestHtons(t *testing.T) {
	b := make([]byte, 2)
	binary.NativeEndian.PutUint16(b, Htons(0x0806))
	if !bytes.Equal(b, []byte{0x08, 0x06}) {
		t.Errorf("Htons(0x0806) in memory = % x", b)
	}
}

// TestPacketRoundTripOnLoopback exercises the real AF_PACKET path: bind to
// one interface, skip our own outgoing copy, read the looped-back frame. It
// needs CAP_NET_RAW, so it is skipped unless run as root in a private
// namespace (`unshare -Urn go test ./internal/capture/`). It only ever sends
// on loopback.
func TestPacketRoundTripOnLoopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil || lo.Flags&net.FlagUp == 0 {
		t.Skip("no usable loopback interface")
	}
	const etherType = 0x88B5 // IEEE local experimental
	conn, err := OpenPacket(lo, etherType, nil)
	if errors.Is(err, unix.EPERM) || (err != nil && errors.Is(errors.Unwrap(err), unix.EPERM)) {
		t.Skip("needs CAP_NET_RAW (run under unshare -Urn)")
	}
	if err != nil {
		t.Skipf("raw sockets unavailable: %v", err)
	}
	defer conn.Close()
	sender, err := OpenSender(lo)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	frame := make([]byte, 60)
	copy(frame[0:6], []byte{0, 0, 0, 0, 0, 0})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], "netsoldier capture test")
	if err := sender.Send(frame); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := sender.Send(frame[:10]); err == nil {
		t.Error("a frame shorter than the Ethernet header was sent")
	}

	buf := make([]byte, 128)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, err := conn.Read(buf)
		if errors.Is(err, ErrTimeout) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf[:n], frame) {
			t.Fatalf("read % x", buf[:n])
		}
		// Only one copy: the outgoing one is skipped.
		if n, err := conn.Read(buf); !errors.Is(err, ErrTimeout) {
			t.Errorf("second read: %d bytes, %v; the outgoing copy should be skipped", n, err)
		}
		return
	}
	t.Fatal("frame not received")
}
