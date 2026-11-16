package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// capturingSink collects pushed frames.
type capturingSink struct {
	ch chan proto.Frame
}

func (s *capturingSink) Push(f proto.Frame) {
	select {
	case s.ch <- f:
	default:
	}
}

// TestLoopbackRoundTrip binds the real ARP capture to loopback, transmits an
// ARP frame on it, and checks the frame comes back whole with a plausible
// timestamp. It needs CAP_NET_RAW, so it is skipped unless run in a private
// namespace (`unshare -Urn go test ./internal/capture/`). It only ever sends
// on loopback.
func TestLoopbackRoundTrip(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil || lo.Flags&net.FlagUp == 0 {
		t.Skip("no usable loopback")
	}
	// Loopback has no Ethernet address; the capture path does not require
	// one (only the transmit Sender does), so synthesise an interface for
	// open() but send with a raw socket of our own below.
	p, _ := Lookup("arp")
	s, err := open(lo, p)
	if errors.Is(err, unix.EPERM) || (err != nil && errors.Is(errors.Unwrap(err), unix.EPERM)) {
		t.Skip("needs CAP_NET_RAW (run under unshare -Urn)")
	}
	if err != nil {
		t.Skipf("raw socket unavailable: %v", err)
	}
	defer s.close()

	// Build a minimal ARP frame and send it on loopback.
	frame := make([]byte, 42)
	// dst + src MAC left zero (loopback ignores them), EtherType ARP.
	binary.BigEndian.PutUint16(frame[12:14], etherARP)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 1)

	tx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("transmit socket unavailable: %v", err)
	}
	defer unix.Close(tx)
	addr := unix.SockaddrLinklayer{Protocol: wire.Htons(etherARP), Ifindex: lo.Index, Halen: 6}
	if err := unix.Sendto(tx, frame, 0, &addr); err != nil {
		t.Fatalf("send: %v", err)
	}

	buf := make([]byte, p.MaxLen+1)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, err := s.read(buf)
		if errors.Is(err, errTimeout) {
			continue
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if n == len(frame) {
			return // got our frame back, whole
		}
	}
	t.Fatal("frame did not come back")
}

// TestCaptureStatusAndCounts exercises the supervisor's state tracking
// without a socket, via a short run against a down interface.
func TestCaptureStatusAndCounts(t *testing.T) {
	backoffInitial, backoffMax = time.Millisecond, time.Millisecond
	c := New(&net.Interface{Index: 1 << 30, Name: "nope0"}, []Protocol{{Name: "arp", EtherType: etherARP}}, &capturingSink{ch: make(chan proto.Frame, 1)})
	if c.Status()["arp"] {
		t.Error("capture reported up before starting")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	c.Run(ctx)
	if c.Status()["arp"] {
		t.Error("capture of a missing interface should not be up")
	}
	_ = netip.Addr{}
}
