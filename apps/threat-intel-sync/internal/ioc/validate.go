package ioc

import (
	"fmt"
	"net"
	"strings"
)

// minDomainLabels mirrors the detection-engine's guard. Validating here as
// well is deliberate duplication: this service is the first place feed data
// lands, and a bad indicator that never enters the store cannot be exported
// to Suricata, Zeek, AdGuard or Vector either. The consumer keeps its own
// check because it must not trust its input even from a sibling service.
const minDomainLabels = 2

// publicSuffixes are suffixes that must never stand alone as an indicator.
// The detection-engine walks parent domains when matching, so "com" as an
// indicator matches every .com name — and the AdGuard export would turn it
// into a filter rule blocking all of them.
var publicSuffixes = map[string]struct{}{
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {},
	"info": {}, "biz": {}, "name": {}, "pro": {}, "app": {}, "dev": {}, "io": {},
	"co": {}, "me": {}, "tv": {}, "cc": {}, "xyz": {}, "top": {}, "online": {},
	"site": {}, "shop": {}, "cloud": {}, "live": {}, "icu": {}, "vip": {},
	"pl": {}, "de": {}, "uk": {}, "fr": {}, "nl": {}, "it": {}, "es": {},
	"cz": {}, "sk": {}, "ru": {}, "ua": {}, "eu": {}, "us": {}, "ca": {},
	"cn": {}, "jp": {}, "br": {}, "in": {}, "au": {}, "ch": {}, "at": {},
	"be": {}, "se": {}, "no": {}, "dk": {}, "fi": {}, "ie": {}, "pt": {},
	"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {}, "me.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "com.br": {}, "com.cn": {},
	"co.jp": {}, "com.pl": {}, "net.pl": {}, "org.pl": {}, "gov.pl": {},
	"co.nz": {}, "co.za": {}, "com.mx": {}, "com.tr": {}, "co.in": {},
	"duckdns.org": {}, "no-ip.org": {}, "ddns.net": {}, "dyndns.org": {},
	"hopto.org": {}, "zapto.org": {}, "ngrok.io": {}, "herokuapp.com": {},
	"azurewebsites.net": {}, "cloudfront.net": {}, "amazonaws.com": {},
	"firebaseapp.com": {}, "web.app": {}, "pages.dev": {}, "workers.dev": {},
	"github.io": {}, "netlify.app": {}, "vercel.app": {}, "glitch.me": {},
}

// Validate normalizes an indicator and reports why it cannot be used.
// Rejected indicators are dropped at ingest rather than stored, so a single
// malformed feed row cannot propagate to every downstream export.
func Validate(i Indicator) (Indicator, error) {
	i.Value = strings.TrimSpace(i.Value)
	if i.Value == "" {
		return i, fmt.Errorf("empty value")
	}

	switch i.Type {
	case TypeDomain:
		v, err := validateDomain(i.Value)
		if err != nil {
			return i, err
		}
		i.Value = v
	case TypeIP:
		v, err := validateIP(i.Value)
		if err != nil {
			return i, err
		}
		i.Value = v
	case TypeURL:
		if len(i.Value) > 2048 {
			return i, fmt.Errorf("url too long")
		}
	case TypeMD5, TypeSHA256, TypeJA3, TypeTLSFP, TypeCertSHA1, TypeCertSHA256:
		i.Value = strings.ToLower(i.Value)
		if strings.ContainsAny(i.Value, " \t\r\n") {
			return i, fmt.Errorf("fingerprint contains whitespace")
		}
	default:
		return i, fmt.Errorf("unknown indicator type %q", i.Type)
	}

	if i.Confidence < 0 || i.Confidence > 100 {
		return i, fmt.Errorf("confidence %d out of range", i.Confidence)
	}
	return i, nil
}

func validateDomain(value string) (string, error) {
	d := strings.ToLower(value)
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")

	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain too long")
	}
	if strings.ContainsAny(d, " \t\r\n/\\?#@:") {
		return "", fmt.Errorf("domain contains illegal characters: %q", value)
	}

	labels := strings.Split(d, ".")
	if len(labels) < minDomainLabels {
		return "", fmt.Errorf("domain %q has %d label(s): too broad to use as an indicator",
			d, len(labels))
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("domain %q has a malformed label %q", d, l)
		}
	}
	if _, isSuffix := publicSuffixes[d]; isSuffix {
		return "", fmt.Errorf("refusing public suffix %q as an indicator", d)
	}
	return d, nil
}

func validateIP(value string) (string, error) {
	v := strings.TrimSpace(value)

	if strings.Contains(v, "/") {
		_, ipnet, err := net.ParseCIDR(v)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		if ones, bits := ipnet.Mask.Size(); ones == 0 && bits > 0 {
			return "", fmt.Errorf("refusing catch-all CIDR %q", value)
		}
		return ipnet.String(), nil
	}

	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP %q", value)
	}
	if parsed.IsLoopback() || parsed.IsUnspecified() {
		return "", fmt.Errorf("refusing loopback/unspecified address %q", value)
	}
	return parsed.String(), nil
}
