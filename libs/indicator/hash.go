package indicator

import (
	"fmt"
	"strings"
)

// hexLen is the exact digest length, in hex digits, of each hash type.
var hexLen = map[string]int{
	TypeMD5:        32,
	TypeJA3:        32, // a JA3 fingerprint is an MD5 digest
	TypeSHA256:     64,
	TypeCertSHA1:   40,
	TypeCertSHA256: 64,
}

// Hash validates a hash or fingerprint indicator and returns it lower-cased.
// Digests must be exactly the right number of hex digits; certificate
// fingerprints may be written with colon separators ("AB:CD:…"), which are
// removed. A TLS client fingerprint must have the JA4 shape
// "t13d1516h2_8daaf6152771_b186095e22b6".
func Hash(t, raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "", fmt.Errorf("empty %s", t)
	}
	if t == TypeTLSFP {
		if !isJA4(v) {
			return "", fmt.Errorf("%s %q is not a JA4-format fingerprint", t, raw)
		}
		return v, nil
	}
	want, ok := hexLen[t]
	if !ok {
		return "", fmt.Errorf("%w %q", ErrUnknownType, t)
	}
	if t == TypeCertSHA1 || t == TypeCertSHA256 {
		v = strings.ReplaceAll(v, ":", "")
	}
	if len(v) != want || !isHex(v) {
		return "", fmt.Errorf("%s %q is not %d hex digits", t, raw, want)
	}
	return v, nil
}

// isJA4 checks the JA4 TLS client fingerprint layout: a 10-character
// header (protocol, TLS version, SNI flag, cipher count, extension count,
// ALPN), then two 12-hex-digit truncated hashes.
func isJA4(v string) bool {
	parts := strings.Split(v, "_")
	if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		return false
	}
	a := parts[0]
	if !strings.ContainsRune("tqd", rune(a[0])) || !isAlnum(a[1:3]) ||
		(a[3] != 'd' && a[3] != 'i') || !isDigits(a[4:8]) || !isAlnum(a[8:10]) {
		return false
	}
	return isHex(parts[1]) && isHex(parts[2])
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return s != ""
}

func isDigits(s string) bool { return allDigits(s) }

func isAlnum(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return s != ""
}
