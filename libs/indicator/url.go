package indicator

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// MaxURLLen bounds a URL indicator. Browsers and proxies cap request lines
// at a few kilobytes; anything longer is not a URL a device will request.
const MaxURLLen = 2048

// URL validates a URL indicator and returns it with a lower-case scheme and
// host, the host in A-label form, an empty path written as "/" and any
// fragment dropped (a fragment is never sent on the wire, so it can never
// be observed).
//
// Only http and https are accepted. The host must be a valid internet host
// name (the Public Suffix List is not consulted: a URL on a shared host is
// still specific) or a global unicast address. User information is refused:
// "http://bank.example@evil.example/" names the wrong host to a human reader,
// and no network sensor records it. Whitespace and control characters are
// refused anywhere in the value.
func URL(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("empty url")
	}
	if len(v) > MaxURLLen {
		return "", fmt.Errorf("url too long (%d bytes)", len(v))
	}
	if hasControlOrSpace(v) {
		return "", fmt.Errorf("url contains whitespace or control characters: %q", raw)
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %v", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("url %q: scheme %q is not http or https", raw, u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("url %q has no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("url %q carries user information", raw)
	}

	host, err := urlHost(u.Hostname())
	if err != nil {
		return "", fmt.Errorf("url %q: %w", raw, err)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || p[0] == '0' {
			return "", fmt.Errorf("url %q has an invalid port", raw)
		}
		host += ":" + p
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + host + path
	if u.RawQuery != "" || u.ForceQuery {
		out += "?" + u.RawQuery
	}
	return out, nil
}

func urlHost(h string) (string, error) {
	if strings.Contains(h, ":") || allDigits(strings.ReplaceAll(h, ".", "")) {
		a, err := ParseAddr(h)
		if err != nil {
			return "", err
		}
		if a.Is6() {
			return "[" + a.String() + "]", nil
		}
		return a.String(), nil
	}
	return hostName(h)
}
