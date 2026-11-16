package capture

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// errTimeout is returned by read when nothing arrived within the socket's
// receive timeout or the wait was interrupted (EINTR). The loop retries.
var errTimeout = errors.New("capture: no frame before the read timeout")

// socket is one AF_PACKET receive socket bound to one interface, plus the
// unbound UDP socket that holds an IP-level multicast membership when the
// protocol needs one. Neither has a port: nothing can connect to the agent.
type socket struct {
	fd      int
	groupFD int // -1 when unused
}

// open creates the capture socket for p on ifi. The socket is created with
// protocol 0, so it receives nothing until bind; the filter is attached
// before bind, so no frame of another kind or from another interface is ever
// queued on it.
func open(ifi *net.Interface, p Protocol) (*socket, error) {
	raw, err := bpf.Assemble(p.Filter)
	if err != nil {
		return nil, fmt.Errorf("%s filter: %w", p.Name, err)
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (the binary needs CAP_NET_RAW): %w", err)
	}
	s := &socket{fd: fd, groupFD: -1}
	fail := func(what string, err error) (*socket, error) {
		s.close()
		return nil, fmt.Errorf("%s %s on %s: %w", p.Name, what, ifi.Name, err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return fail("attach filter", err)
	}
	// Our own probes and isolation frames are not news to device-inventory.
	// Older kernels lack the option; read also skips PACKET_OUTGOING.
	_ = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: wire.Htons(p.EtherType), Ifindex: ifi.Index}); err != nil {
		return fail("bind", err)
	}
	for _, g := range p.LinkGroups {
		mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: uint16(len(g))}
		copy(mreq.Address[:], g)
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			return fail("join "+g.String(), err)
		}
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		return fail("set read timeout", err)
	}
	if p.IPGroup.IsValid() {
		gfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fail("membership socket", err)
		}
		s.groupFD = gfd
		mreq := unix.IPMreqn{Multiaddr: p.IPGroup.As4(), Ifindex: int32(ifi.Index)}
		if err := unix.SetsockoptIPMreqn(gfd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq); err != nil {
			return fail("join "+p.IPGroup.String(), err)
		}
	}
	return s, nil
}

// read returns the length of the next frame that arrived from the wire. It
// is the frame's full length even when that exceeds buf (MSG_TRUNC), which is
// how oversized frames are recognised. EAGAIN and EINTR are errTimeout: with
// SO_RCVTIMEO the kernel never restarts recvfrom after a signal, and the Go
// runtime signals its threads routinely.
func (s *socket) read(buf []byte) (int, error) {
	for {
		n, from, err := unix.Recvfrom(s.fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return 0, errTimeout
			}
			return 0, fmt.Errorf("recvfrom: %w", err)
		}
		if sll, ok := from.(*unix.SockaddrLinklayer); ok && sll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return n, nil
	}
}

func (s *socket) close() {
	unix.Close(s.fd)
	if s.groupFD >= 0 {
		unix.Close(s.groupFD) // closing drops the membership
	}
}

// CheckRaw opens and closes an AF_PACKET socket, so a missing CAP_NET_RAW is
// a start-up error with a clear message rather than a capture that retries
// forever.
func CheckRaw() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("cannot open an AF_PACKET socket (the binary needs the CAP_NET_RAW file capability "+
			"and NET_RAW in the container's bounding set): %w", err)
	}
	return unix.Close(fd)
}
