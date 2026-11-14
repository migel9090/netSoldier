// Package capture opens the sockets the passive listeners read from, always
// bound to one interface: AF_PACKET sockets for ARP, LLDP and DHCP (which
// need the Ethernet source to check what a frame claims), and UDP multicast
// sockets for mDNS and SSDP.
//
// Runtime requirements: AF_PACKET needs CAP_NET_RAW; SO_BINDTODEVICE needs
// CAP_NET_RAW on kernels before 5.7. Nothing here binds a privileged port.
package capture

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrTimeout is returned by PacketConn.Read when no frame arrived within the
// read timeout or the wait was interrupted (EINTR). Callers loop on it.
var ErrTimeout = errors.New("capture: no frame before the read timeout")

// ResolveInterface returns the named interface, or the interface that holds
// the IPv4 default route when name is empty.
func ResolveInterface(name string) (*net.Interface, error) {
	if name == "" {
		var err error
		if name, err = defaultRouteInterface("/proc/net/route"); err != nil {
			return nil, err
		}
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %q is down", name)
	}
	return ifi, nil
}

func defaultRouteInterface(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("no DISCOVERY_INTERFACE set and the routing table is unreadable: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// Iface Destination Gateway Flags ... ; RTF_UP = 0x1
		fields := strings.Fields(sc.Text())
		if len(fields) >= 4 && fields[1] == "00000000" {
			var flags uint64
			if _, err := fmt.Sscanf(fields[3], "%x", &flags); err == nil && flags&0x1 != 0 {
				return fields[0], nil
			}
		}
	}
	return "", errors.New("no DISCOVERY_INTERFACE set and there is no IPv4 default route to infer it from")
}

// PacketConn is an AF_PACKET socket that only sees one EtherType on one
// interface.
type PacketConn struct {
	fd int
}

// OpenPacket opens a raw socket for ethertype on ifi. The socket is created
// with protocol 0, so it receives nothing until bind attaches it to the
// interface; an optional classic-BPF filter is attached before that, so no
// frame from another interface or of another kind is ever queued. groups are
// link-layer multicast addresses the NIC must accept (LLDP's 01:80:c2:00:00:0e
// is dropped by most NIC filters unless something joins it).
func OpenPacket(ifi *net.Interface, ethertype uint16, filter []unix.SockFilter, groups ...net.HardwareAddr) (*PacketConn, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	c := &PacketConn{fd: fd}
	if len(filter) > 0 {
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
			c.Close()
			return nil, fmt.Errorf("attach filter: %w", err)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: Htons(ethertype), Ifindex: ifi.Index}); err != nil {
		c.Close()
		return nil, fmt.Errorf("bind to %s: %w", ifi.Name, err)
	}
	for _, g := range groups {
		mreq := unix.PacketMreq{Ifindex: int32(ifi.Index), Type: unix.PACKET_MR_MULTICAST, Alen: uint16(len(g))}
		copy(mreq.Address[:], g)
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			c.Close()
			return nil, fmt.Errorf("join %s on %s: %w", g, ifi.Name, err)
		}
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		c.Close()
		return nil, fmt.Errorf("set read timeout: %w", err)
	}
	return c, nil
}

// InterfaceWatch reports, at most once per interval, whether the interface a
// listener is bound to is still there and up. UDP sockets bound to a device
// keep "working" (silently receiving nothing) when it goes down, so without
// this an mDNS or SSDP listener would stay ready on a dead interface.
type InterfaceWatch struct {
	ifi      *net.Interface
	interval time.Duration
	last     time.Time
}

// NewInterfaceWatch watches ifi, checking at most every interval.
func NewInterfaceWatch(ifi *net.Interface, interval time.Duration) *InterfaceWatch {
	return &InterfaceWatch{ifi: ifi, interval: interval, last: time.Now()}
}

// Check returns an error once the interface has gone down or away.
func (w *InterfaceWatch) Check() error {
	if time.Since(w.last) < w.interval {
		return nil
	}
	w.last = time.Now()
	cur, err := net.InterfaceByIndex(w.ifi.Index)
	if err != nil || cur.Name != w.ifi.Name {
		return fmt.Errorf("interface %s is gone", w.ifi.Name)
	}
	if cur.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s went down", w.ifi.Name)
	}
	return nil
}

// Read returns the next frame that arrived from the wire. Frames this host
// transmitted itself are skipped. EAGAIN and EINTR are reported as
// ErrTimeout: with SO_RCVTIMEO set the kernel never restarts recvfrom after
// a signal, and the Go runtime signals its threads routinely.
func (c *PacketConn) Read(buf []byte) (int, error) {
	for {
		n, from, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				return 0, ErrTimeout
			}
			return 0, fmt.Errorf("recvfrom: %w", err)
		}
		if sll, ok := from.(*unix.SockaddrLinklayer); ok && sll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		return n, nil
	}
}

// Close releases the socket.
func (c *PacketConn) Close() error { return unix.Close(c.fd) }

// Sender transmits complete Ethernet frames on one interface. Its socket has
// protocol 0, so the kernel queues nothing for it to read.
type Sender struct {
	fd    int
	iface *net.Interface
}

// OpenSender opens a transmit-only AF_PACKET socket for ifi.
func OpenSender(ifi *net.Interface) (*Sender, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	return &Sender{fd: fd, iface: ifi}, nil
}

// Send transmits frame, whose first 14 bytes are the Ethernet header.
func (s *Sender) Send(frame []byte) error {
	if len(frame) < 14 {
		return errors.New("capture: frame shorter than an Ethernet header")
	}
	addr := unix.SockaddrLinklayer{
		Protocol: Htons(binary.BigEndian.Uint16(frame[12:14])),
		Ifindex:  s.iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:], frame[0:6])
	return unix.Sendto(s.fd, frame, 0, &addr)
}

// Close releases the socket.
func (s *Sender) Close() error { return unix.Close(s.fd) }

// ListenMulticast opens a UDP socket on port that only accepts datagrams
// arriving on ifi (SO_BINDTODEVICE), joined to group on that interface. The
// group is joined by interface index, so this does not depend on a multicast
// route existing yet.
func ListenMulticast(ctx context.Context, ifi *net.Interface, group net.IP, port int) (*net.UDPConn, error) {
	g := group.To4()
	if g == nil {
		return nil, fmt.Errorf("group %s is not IPv4", group)
	}
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
				return
			}
			serr = unix.BindToDevice(int(fd), ifi.Name)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}
	conn := pc.(*net.UDPConn)
	rc, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		mreq := &unix.IPMreqn{Multiaddr: [4]byte(g), Ifindex: int32(ifi.Index)}
		if serr = unix.SetsockoptIPMreqn(int(fd), unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq); serr != nil {
			return
		}
		// Linux otherwise delivers every group any socket on this host
		// joined on the port, not just ours.
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_ALL, 0)
	}); err != nil {
		conn.Close()
		return nil, err
	}
	if serr != nil {
		conn.Close()
		return nil, fmt.Errorf("join %s on %s: %w", g, ifi.Name, serr)
	}
	return conn, nil
}

// Htons converts to network byte order, which sockaddr_ll expects.
func Htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
