package iocmatch

import (
	"fmt"
	"strings"
)

// publicSuffixes are suffixes that must never be accepted as a standalone
// domain indicator.
//
// MatchDomain walks every parent of a queried name, so an indicator of "com"
// would match EVERY .com lookup. Feed data is third-party and
// machine-generated: one malformed URLhaus row, a MISP attribute whose value
// is just a TLD, or a parser that trims one label too many is enough. With
// auto-block at critical/90 that escalates to a DNS sinkhole on the entire
// internet. The list is intentionally short — the real guard is the label
// count below — and covers the suffixes a home network actually resolves
// plus the multi-label ones a naive "strip the last two labels" would miss.
var publicSuffixes = map[string]struct{}{
	// generic
	"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {}, "int": {},
	"info": {}, "biz": {}, "name": {}, "pro": {}, "app": {}, "dev": {}, "io": {},
	"co": {}, "me": {}, "tv": {}, "cc": {}, "xyz": {}, "top": {}, "online": {},
	"site": {}, "shop": {}, "cloud": {}, "live": {}, "icu": {}, "vip": {},
	// country codes seen on a European home network
	"pl": {}, "de": {}, "uk": {}, "fr": {}, "nl": {}, "it": {}, "es": {},
	"cz": {}, "sk": {}, "ru": {}, "ua": {}, "eu": {}, "us": {}, "ca": {},
	"cn": {}, "jp": {}, "br": {}, "in": {}, "au": {}, "ch": {}, "at": {},
	"be": {}, "se": {}, "no": {}, "dk": {}, "fi": {}, "ie": {}, "pt": {},
	// multi-label suffixes
	"co.uk": {}, "org.uk": {}, "gov.uk": {}, "ac.uk": {}, "me.uk": {},
	"com.au": {}, "net.au": {}, "org.au": {}, "com.br": {}, "com.cn": {},
	"co.jp": {}, "com.pl": {}, "net.pl": {}, "org.pl": {}, "gov.pl": {},
	"co.nz": {}, "co.za": {}, "com.mx": {}, "com.tr": {}, "co.in": {},
	// dynamic-DNS parents: legitimate to see, catastrophic to block wholesale
	"duckdns.org": {}, "no-ip.org": {}, "ddns.net": {}, "dyndns.org": {},
	"hopto.org": {}, "zapto.org": {}, "serveo.net": {}, "ngrok.io": {},
	"herokuapp.com": {}, "azurewebsites.net": {}, "cloudfront.net": {},
	"amazonaws.com": {}, "blob.core.windows.net": {}, "firebaseapp.com": {},
	"web.app": {}, "pages.dev": {}, "workers.dev": {}, "github.io": {},
	"netlify.app": {}, "vercel.app": {}, "glitch.me": {}, "repl.co": {},
}

// minDomainLabels is the real guard: a domain indicator must have at least
// two labels, so no bare TLD can ever enter the matcher.
const minDomainLabels = 2

// ValidateDomainIndicator normalizes a feed-supplied domain and rejects
// anything too broad to block safely.
func ValidateDomainIndicator(value string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(value))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")

	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain too long (%d bytes)", len(d))
	}
	if strings.ContainsAny(d, " \t\r\n/\\?#@:") {
		return "", fmt.Errorf("domain contains illegal characters: %q", value)
	}

	labels := strings.Split(d, ".")
	if len(labels) < minDomainLabels {
		return "", fmt.Errorf("domain %q has %d label(s): a bare suffix would match every "+
			"name under it", d, len(labels))
	}
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("domain %q has an empty label", d)
		}
		if len(l) > 63 {
			return "", fmt.Errorf("domain %q has an over-long label", d)
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("domain %q has a malformed label %q", d, l)
		}
	}

	if _, isSuffix := publicSuffixes[d]; isSuffix {
		return "", fmt.Errorf("refusing public suffix %q as an indicator: it would match "+
			"every domain registered under it", d)
	}

	return d, nil
}
