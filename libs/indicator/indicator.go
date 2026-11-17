// Package indicator is the single definition of what netSoldier accepts as
// an indicator of compromise.
//
// Feed content is third-party input, and a match can end with a device cut
// off the network, so a bad indicator is a household outage. The rules used
// to live twice — once in threat-intel-sync at ingest, once in the
// detection-engine's matcher — and both copies were deny-lists that had
// drifted into accepting `*.*.*`, `0.0.0.0/1`, the home gateway and
// non-hex hashes. Both services now call this package, so the two sides can
// no longer disagree.
//
// Everything here is an allow-list: a value is accepted only if it has the
// exact shape of its type, and then returned in one canonical spelling so
// both sides key their maps identically.
//
// Whether a well-formed indicator may be acted on is a second question,
// answered by NeverBlock / CheckBlockable (neverblock.go): popular and
// shared hosts and public resolvers must never become an automatic block.
package indicator

import (
	"errors"
	"fmt"
)

// Indicator type names. These are the wire values of the threat-intel-sync
// JSON export, so they must not change.
const (
	TypeDomain     = "domain"
	TypeIP         = "ip"
	TypeURL        = "url"
	TypeMD5        = "md5"
	TypeSHA256     = "sha256"
	TypeJA3        = "ja3"
	TypeTLSFP      = "tlsfp" // TLS client fingerprint (JA4-format)
	TypeCertSHA1   = "cert-sha1"
	TypeCertSHA256 = "cert-sha256"
)

// Length bounds for free-text fields. Values are truncated, not refused: a
// long analyst note is not a reason to lose the indicator it describes.
const (
	MaxTextLen      = 512  // threat / description
	MaxReferenceLen = 2048 // reference URL or free text
	MaxSourceLen    = 64
	MaxTagLen       = 64
	MaxTags         = 32
)

// ErrUnknownType reports a type name this package does not define at all.
// Callers that recognise a type but cannot use it (the matcher has no URL
// lookup) must count that separately: an unsupported type is not evidence of
// a broken or hostile feed, an unknown one is.
var ErrUnknownType = errors.New("unknown indicator type")

// KnownType reports whether t is one of the defined indicator types.
func KnownType(t string) bool {
	switch t {
	case TypeDomain, TypeIP, TypeURL, TypeMD5, TypeSHA256, TypeJA3, TypeTLSFP,
		TypeCertSHA1, TypeCertSHA256:
		return true
	}
	return false
}

// Value validates value as an indicator of type t and returns its canonical
// form. Errors for an undefined type wrap ErrUnknownType.
func Value(t, value string) (string, error) {
	switch t {
	case TypeDomain:
		return Domain(value)
	case TypeIP:
		return IP(value)
	case TypeURL:
		return URL(value)
	case TypeMD5, TypeSHA256, TypeJA3, TypeTLSFP, TypeCertSHA1, TypeCertSHA256:
		return Hash(t, value)
	default:
		return "", fmt.Errorf("%w %q", ErrUnknownType, t)
	}
}
