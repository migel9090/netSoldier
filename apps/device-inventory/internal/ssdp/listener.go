package ssdp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/capture"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

var group = net.IPv4(239, 255, 255, 250)

const port = 1900

// Listener passively captures SSDP NOTIFY announcements on one interface and
// offers the UPnP product token as a (weak) name for the device holding the
// datagram's source address.
type Listener struct {
	iface string
	ch    chan<- discovery.Sighting
}

// NewListener returns a listener for iface ("" = default-route interface).
func NewListener(iface string, ch chan<- discovery.Sighting) *Listener {
	return &Listener{iface: iface, ch: ch}
}

// Run reads until ctx is done or the socket fails.
func (l *Listener) Run(ctx context.Context, up func()) error {
	ifi, err := capture.ResolveInterface(l.iface)
	if err != nil {
		return err
	}
	conn, err := capture.ListenMulticast(ctx, ifi, group, port)
	if err != nil {
		return err
	}
	defer conn.Close()
	up()

	watch := capture.NewInterfaceWatch(ifi, 5*time.Second)
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		if err := watch.Check(); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		metrics.FramesReceived.WithLabelValues("ssdp").Inc()
		s, err := ParseDatagram(buf[:n], src.IP)
		if err != nil {
			metrics.FramesRejected.WithLabelValues("ssdp", discovery.RejectReason(err)).Inc()
			continue
		}
		select {
		case l.ch <- s:
		case <-ctx.Done():
		}
	}
	return nil
}

// ParseDatagram turns an ssdp:alive NOTIFY received from src into a sighting
// for its sender. It does no I/O. The address is always the datagram's
// source: a LOCATION naming a different host is a proxy or a forgery and the
// message is dropped, so one host cannot put a name on another's address by
// announcing it.
func ParseDatagram(msg []byte, src net.IP) (discovery.Sighting, error) {
	ip, ok := discovery.UsableIPv4(src)
	if !ok {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	line, _, _ := bytes.Cut(msg, []byte("\n"))
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(line))), "NOTIFY * HTTP/1.") {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	h := parseHeaders(msg)
	if nts := h["nts"]; nts != "" && !strings.EqualFold(nts, "ssdp:alive") {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	if loc := h["location"]; loc != "" {
		u, err := url.Parse(loc)
		if err != nil {
			return discovery.Sighting{}, discovery.ErrMalformed
		}
		if host, ok := discovery.ParseUsableIPv4(u.Hostname()); ok && host != ip {
			return discovery.Sighting{}, discovery.ErrIgnored
		}
	}
	name := extractProductName(h["server"])
	if name == "" {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	return discovery.Sighting{Source: discovery.SourceSSDP, IP: ip, Name: name}, nil
}

// parseHeaders reads "Name: value" lines; names are lower-cased and the first
// occurrence wins. Input is bounded by the read buffer.
func parseHeaders(msg []byte) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(msg))
	for scanner.Scan() {
		if k, v, ok := strings.Cut(scanner.Text(), ":"); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			if _, dup := headers[k]; !dup {
				headers[k] = strings.TrimSpace(v)
			}
		}
	}
	return headers
}

// extractProductName picks the product from a UPnP SERVER header, which is
// "OS/version UPnP/version product/version": "Linux/3.14 UPnP/1.0
// Sonos/63.2" gives "Sonos". The OS token before UPnP/ is never a name
// (it used to make every Linux box "Linux"). Headers without a UPnP token
// give "".
func extractProductName(server string) string {
	i := indexASCIIFold(server, "upnp/")
	if i < 0 {
		return ""
	}
	rest := server[i:]
	end := strings.IndexAny(rest, " ,")
	if end < 0 {
		return ""
	}
	rest = strings.TrimLeft(rest[end:], " ,")
	if j := strings.IndexAny(rest, "/("); j >= 0 {
		rest = rest[:j]
	}
	return discovery.SanitizeText(rest, discovery.MaxNameLen)
}

// indexASCIIFold finds an ASCII needle in s ignoring ASCII case, returning a
// byte offset into s itself. (Searching strings.ToLower(s) instead returns
// offsets into a string of a different length whenever s holds invalid UTF-8
// or runes whose lower case is longer, which the fuzzer turned into a
// slice-bounds panic.)
func indexASCIIFold(s, needle string) int {
	lower := func(c byte) byte {
		if 'A' <= c && c <= 'Z' {
			return c + 'a' - 'A'
		}
		return c
	}
outer:
	for i := 0; i+len(needle) <= len(s); i++ {
		for j := 0; j < len(needle); j++ {
			if lower(s[i+j]) != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
