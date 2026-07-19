package export

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// WriteZeekIntel writes indicators in Zeek Intel framework format
// (tab-separated, loadable via Intel::read_files).
func WriteZeekIntel(w io.Writer, indicators []ioc.Indicator) {
	fmt.Fprintln(w, "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url")
	for _, ind := range indicators {
		zeekType := mapZeekType(ind)
		if zeekType == "" {
			continue
		}
		desc := ind.Threat
		if desc == "" {
			desc = "-"
		}
		ref := ind.Reference
		if ref == "" {
			ref = "-"
		}
		source := ind.Source
		if source == "" {
			source = "netsoldier"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ind.Value, zeekType, source, desc, ref)
	}
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
