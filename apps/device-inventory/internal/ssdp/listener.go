package ssdp

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// Listener passively captures SSDP NOTIFY announcements and extracts
// device information from the SERVER and LOCATION headers.
type Listener struct {
	ch chan<- discovery.Info
}

func NewListener(ch chan<- discovery.Info) *Listener {
	return &Listener{ch: ch}
}

func (l *Listener) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	slog.Info("ssdp listener started")
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		if src == nil || n < 10 {
			continue
		}

		headers := parseHeaders(string(buf[:n]))
		server := headers["server"]
		location := headers["location"]
		if server == "" && location == "" {
			continue
		}

		ip := src.IP.String()
		if location != "" {
			if u, err := url.Parse(location); err == nil && u.Hostname() != "" {
				ip = u.Hostname()
			}
		}

		l.ch <- discovery.Info{
			IP:       ip,
			Hostname: extractProductName(server),
			Meta:     server,
			Protocol: "ssdp",
		}
	}
}

func parseHeaders(msg string) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(msg))
	for scanner.Scan() {
		line := scanner.Text()
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return headers
}

// extractProductName picks the product token from a SERVER header like
// "Linux/5.15 UPnP/1.0 MiniDLNA/1.3".
func extractProductName(server string) string {
	if server == "" {
		return ""
	}
	parts := strings.Fields(server)
	for _, p := range parts {
		lower := strings.ToLower(p)
		if strings.HasPrefix(lower, "upnp/") || strings.HasPrefix(lower, "http/") {
			continue
		}
		if name, _, ok := strings.Cut(p, "/"); ok {
			return name
		}
	}
	return ""
}
