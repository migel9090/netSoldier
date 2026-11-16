package discovery

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds for LAN-learned strings. DHCP option 12 and DNS names can be 255
// bytes; nothing a person reads in an inventory needs that much.
const (
	MaxNameLen        = 64
	MaxVendorClassLen = 128
)

// Errors a parser returns for frames it refuses. Listeners count them by
// reason; ErrLinkMismatch is the one that indicates forgery.
var (
	// ErrLinkMismatch: the MAC asserted inside the payload is not the
	// Ethernet source of the frame that carried it.
	ErrLinkMismatch = errors.New("claimed MAC is not the frame's link-layer source")
	// ErrMalformed: the frame is truncated or internally inconsistent.
	ErrMalformed = errors.New("malformed frame")
	// ErrIgnored: a well-formed frame that carries nothing the inventory uses.
	ErrIgnored = errors.New("frame carries no usable claim")
)

// RejectReason maps a parser error to a metric label.
func RejectReason(err error) string {
	switch {
	case errors.Is(err, ErrLinkMismatch):
		return "link_mismatch"
	case errors.Is(err, ErrIgnored):
		return "ignored"
	default:
		return "malformed"
	}
}

// CanonicalMAC returns hw as a lower-case colon-separated string when it is a
// 6-byte unicast address that is not all zeros. Group (multicast/broadcast)
// and zero addresses never identify a device.
func CanonicalMAC(hw []byte) (string, bool) {
	if len(hw) != 6 || hw[0]&0x01 != 0 {
		return "", false
	}
	if hw[0]|hw[1]|hw[2]|hw[3]|hw[4]|hw[5] == 0 {
		return "", false
	}
	return net.HardwareAddr(hw).String(), true
}

// ParseMAC accepts aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff in any case and
// returns the canonical unicast form.
func ParseMAC(s string) (string, bool) {
	if len(s) != 17 {
		return "", false
	}
	hw, err := net.ParseMAC(strings.ReplaceAll(s, "-", ":"))
	if err != nil {
		return "", false
	}
	return CanonicalMAC(hw)
}

// IsRandomizedMAC reports whether a canonical MAC has the locally
// administered bit set, i.e. is a privacy address (iOS 14+, Android 10+,
// Windows 10+) rather than one burned in by the vendor.
func IsRandomizedMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) == 6 && hw[0]&0x02 != 0
}

// UsableIPv4 returns the canonical form of an address a LAN device can hold:
// IPv4 unicast, not unspecified, loopback, multicast or limited broadcast.
func UsableIPv4(ip net.IP) (string, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", false
	}
	a = a.Unmap()
	if !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || a.As4()[0] == 0 {
		return "", false
	}
	return a.String(), true
}

// ParseUsableIPv4 is UsableIPv4 for a textual address.
func ParseUsableIPv4(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return UsableIPv4(a.AsSlice())
}

// SanitizeText reduces a LAN-learned string to something safe to store and
// show: invalid UTF-8, control characters and format characters (bidi
// overrides, zero-width joiners, BOM) are dropped, every run of white space
// becomes one space, the ends are trimmed, and the result is cut to at most
// max bytes on a rune boundary.
func SanitizeText(s string, max int) string {
	var b strings.Builder
	pendingSpace := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == utf8.RuneError && size <= 1:
			continue
		case unicode.IsSpace(r):
			pendingSpace = b.Len() > 0
			continue
		case !unicode.IsPrint(r):
			continue
		}
		need := utf8.RuneLen(r)
		if pendingSpace {
			need++
		}
		if b.Len()+need > max {
			break
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(r)
	}
	return b.String()
}
