package export

import (
	"bytes"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

func TestWriteZeekIntelTypes(t *testing.T) {
	indicators := []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "evil.example.com", Source: "threatfox", Threat: "c2"},
		{Type: ioc.TypeIP, Value: "203.0.113.7"},
		{Type: ioc.TypeIP, Value: "198.51.100.0/24"},
		{Type: ioc.TypeJA3, Value: "db8a6f4f9f8195ea17db377175d2cb08"},
		{Type: ioc.TypeTLSFP, Value: "t13d3012h2_1d37bd780c83_882d495ac381"},
		{Type: ioc.TypeCertSHA1, Value: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{Type: ioc.TypeCertSHA256, Value: strings.Repeat("ab", 32)},
		{Type: "unknown-type", Value: "dropped"},
	}

	var buf bytes.Buffer
	WriteZeekIntel(&buf, indicators)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	if !strings.HasPrefix(lines[0], "#fields\tindicator\tindicator_type\t") {
		t.Fatalf("missing #fields header, got %q", lines[0])
	}
	// unknown-type is dropped; everything else produces one row
	if got, want := len(lines)-1, 7; got != want {
		t.Fatalf("expected %d indicator rows, got %d:\n%s", want, got, buf.String())
	}

	wantTypes := map[string]string{
		"evil.example.com":                         "Intel::DOMAIN",
		"203.0.113.7":                              "Intel::ADDR",
		"198.51.100.0/24":                          "Intel::SUBNET",
		"db8a6f4f9f8195ea17db377175d2cb08":         "Intel::JA3",
		"t13d3012h2_1d37bd780c83_882d495ac381":     "Intel::TLSFP",
		"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": "Intel::CERT_HASH",
		strings.Repeat("ab", 32):                   "Intel::CERT_HASH",
	}
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) != 5 {
			t.Errorf("row has %d fields, want 5: %q", len(fields), line)
			continue
		}
		want, ok := wantTypes[fields[0]]
		if !ok {
			t.Errorf("unexpected indicator %q", fields[0])
			continue
		}
		if fields[1] != want {
			t.Errorf("indicator %q: type %q, want %q", fields[0], fields[1], want)
		}
		if strings.Contains(line, "dropped") {
			t.Errorf("unknown type leaked into export: %q", line)
		}
	}

	// meta.source falls back to "netsoldier", desc/url to "-"
	ipRow := lines[2]
	if !strings.Contains(ipRow, "netsoldier") || !strings.HasSuffix(ipRow, "-") {
		t.Errorf("missing meta fallbacks: %q", ipRow)
	}
}
