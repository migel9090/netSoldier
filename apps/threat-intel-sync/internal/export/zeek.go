package export

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/indicator"
)

// WriteZeekIntel writes indicators in Zeek Intel framework format
// (tab-separated, loadable via Intel::read_files).
//
// Every column is escaped with zeekField. Threat and Reference used to be
// written raw, so a feed row whose threat name held a tab and a newline
// injected an arbitrary well-formed line such as "0.0.0.0/0 Intel::SUBNET"
// into the sensor's intel set.
func WriteZeekIntel(w io.Writer, indicators []ioc.Indicator) {
	fmt.Fprintln(w, "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url")
	for _, ind := range indicators {
		zeekType := mapZeekType(ind)
		if zeekType == "" || !exportable("zeek", ind) {
			continue
		}
		value := ind.Value
		if ind.Type == ioc.TypeURL {
			var ok bool
			if value, ok = zeekURL(ind.Value); !ok {
				continue
			}
		}
		source := ind.Source
		if source == "" {
			source = "netsoldier"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", zeekField(value), zeekType,
			zeekField(source), zeekField(ind.Threat), zeekField(ind.Reference))
	}
}

// zeekField makes a value safe for one column of a Zeek ASCII input file.
// Text removes control characters (ingest already did; this is the second
// line of defence), then the separator, line breaks and the backslash are
// written as \xHH — the escape syntax Zeek's ASCII reader decodes. An empty
// value becomes "-", the unset marker, and a value that happens to equal a
// marker is escaped so data can never be read as one.
func zeekField(s string) string {
	s = indicator.Text(s, indicator.MaxReferenceLen)
	switch s {
	case "":
		return "-"
	case "-", "(empty)":
		return `\x` + fmt.Sprintf("%02x", s[0]) + s[1:]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '\t' || c == '\n' || c == '\r' || c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// zeekURL converts a URL indicator to the form the Intel framework matches:
// Intel::URL is "a complete URL without the prefix http://" — what
// HTTP::build_url produces, the Host (lower-case, port appended only when
// it is not 80) followed by the request URI. Keeping the scheme meant no
// URL indicator ever matched. HTTPS URLs are skipped: their request line is
// encrypted, so Zeek can never observe them.
func zeekURL(u string) (string, bool) {
	rest, ok := strings.CutPrefix(u, "http://")
	if !ok {
		return "", false
	}
	hostport, path, found := strings.Cut(rest, "/")
	if !found {
		path = ""
	}
	hostport = strings.TrimSuffix(hostport, ":80")
	return hostport + "/" + path, true
}

func mapZeekType(ind ioc.Indicator) string {
	switch ind.Type {
	case ioc.TypeDomain:
		return "Intel::DOMAIN"
	case ioc.TypeIP:
		if strings.Contains(ind.Value, "/") {
			return "Intel::SUBNET"
		}
		return "Intel::ADDR"
	case ioc.TypeURL:
		return "Intel::URL"
	case ioc.TypeMD5, ioc.TypeSHA256:
		return "Intel::FILE_HASH"
	case ioc.TypeCertSHA1, ioc.TypeCertSHA256:
		return "Intel::CERT_HASH"
	case ioc.TypeJA3:
		return "Intel::JA3"
	case ioc.TypeTLSFP:
		// first-party type (JA4-format TLS client fingerprint), registered by
		// netsoldier-intel.zeek on the sensor as Intel::TLSFP
		return "Intel::TLSFP"
	default:
		return ""
	}
}

// HandleZeekIntel returns an HTTP handler serving the full IoC store
// in Zeek Intel framework format.
func HandleZeekIntel(store *ioc.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		WriteZeekIntel(w, store.All())
	}
}
