package export

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/prometheus/client_golang/prometheus"
)

// TestAuditZeekInjection (TI-1): one feed row whose threat field held a tab
// and a newline injected a well-formed "0.0.0.0/0 Intel::SUBNET" line into
// intel.dat, and a reference did the same for the home gateway. Every line
// must now have exactly five fields and only the two real indicators.
func TestAuditZeekInjection(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertAll([]ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "c2.evil.example", Source: "misp",
			Threat: "seen in campaign X\nsecond line of the analyst note\twith a tab"},
		{Type: ioc.TypeIP, Value: "203.0.113.7", Source: "threatfox",
			Threat: "Mozi\t-\n0.0.0.0/0\tIntel::SUBNET\tthreatfox\tinjected"},
		{Type: ioc.TypeIP, Value: "203.0.113.8", Source: "threatfox",
			Reference: "https://x/\n192.168.1.1\tIntel::ADDR\tthreatfox\tinjected-gateway\t-"},
	})
	var buf bytes.Buffer
	WriteZeekIntel(&buf, s.All())
	assertZeekWellFormed(t, buf.String(), 3)
	if strings.Contains(buf.String(), "\n0.0.0.0/0\t") || strings.Contains(buf.String(), "\n192.168.1.1\t") {
		t.Errorf("injected indicator line in intel.dat:\n%s", buf.String())
	}
}

// TestZeekEscapesUntrustedFieldsDirectly bypasses the store (and so ingest
// validation): the exporter alone must still produce a well-formed file.
func TestZeekEscapesUntrustedFieldsDirectly(t *testing.T) {
	var buf bytes.Buffer
	WriteZeekIntel(&buf, []ioc.Indicator{
		{Type: ioc.TypeIP, Value: "203.0.113.7", Source: "a\tb",
			Threat: "Mozi\t-\n0.0.0.0/0\tIntel::SUBNET\tx\tinjected", Reference: `C:\path\x09`},
		{Type: ioc.TypeIP, Value: "0.0.0.0/0", Source: "hostile"},             // invalid: dropped
		{Type: ioc.TypeDomain, Value: "evil.example\n0.0.0.0/0", Source: "h"}, // invalid: dropped
		{Type: ioc.TypeDomain, Value: "evil.example", Threat: "-"},
		{Type: ioc.TypeDomain, Value: "evil2.example", Threat: "(empty)"},
	})
	lines := assertZeekWellFormed(t, buf.String(), 3)
	if !strings.Contains(lines[1], `C:\x5cpath\x5cx09`) {
		t.Errorf("backslash not escaped: %q", lines[1])
	}
	if f := strings.Split(lines[2], "\t"); f[3] != `\x2d` {
		t.Errorf("a literal '-' must not read as Zeek's unset marker: %q", lines[2])
	}
	if f := strings.Split(lines[3], "\t"); f[3] != `\x28empty)` {
		t.Errorf("a literal '(empty)' must not read as Zeek's empty marker: %q", lines[3])
	}
}

// TestZeekURLForm (TI-9): Intel::URL is matched against HTTP::build_url,
// which has no scheme; the exported URL used to keep "http://" and so never
// matched. HTTPS URLs are not observable by Zeek and are left out.
func TestZeekURLForm(t *testing.T) {
	var buf bytes.Buffer
	WriteZeekIntel(&buf, []ioc.Indicator{
		{Type: ioc.TypeURL, Value: "http://evil.example/payload.exe"},
		{Type: ioc.TypeURL, Value: "http://evil.example:8080/a?b=c"},
		{Type: ioc.TypeURL, Value: "http://45.61.49.78/razor/r4z0r.mips"},
		{Type: ioc.TypeURL, Value: "https://evil.example/secret"},
	})
	got := map[string]bool{}
	for _, l := range assertZeekWellFormed(t, buf.String(), 3)[1:] {
		f := strings.Split(l, "\t")
		if f[1] != "Intel::URL" {
			t.Errorf("type %q", f[1])
		}
		got[f[0]] = true
	}
	for _, want := range []string{"evil.example/payload.exe", "evil.example:8080/a?b=c", "45.61.49.78/razor/r4z0r.mips"} {
		if !got[want] {
			t.Errorf("missing Zeek URL %q in %v", want, got)
		}
	}
}

// TestAuditAdGuardExport (TI-2, export half): "*.*.*" was exported as
// "||*.*^" and filter-rule modifiers passed straight through.
func TestAuditAdGuardExport(t *testing.T) {
	var buf bytes.Buffer
	WriteAdGuard(&buf, []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "*.*"},
		{Type: ioc.TypeDomain, Value: "evil.example^$dnsrewrite=203.0.113.9"},
		{Type: ioc.TypeDomain, Value: "a.b|c^$important"},
		{Type: ioc.TypeDomain, Value: "co.uk"},
		{Type: ioc.TypeDomain, Value: "EVIL.example"}, // not canonical: dropped
		{Type: ioc.TypeIP, Value: "203.0.113.9"},      // not a domain
		{Type: ioc.TypeDomain, Value: "c2.evil.example"},
	})
	rules := 0
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.HasPrefix(l, "!") {
			continue
		}
		rules++
		if l != "||c2.evil.example^" {
			t.Errorf("unexpected rule %q", l)
		}
	}
	if rules != 1 || !strings.Contains(buf.String(), "! Entries: 1\n") {
		t.Errorf("want exactly one rule and a matching count:\n%s", buf.String())
	}
}

// TestExportersDropInvalidValues: every raw format refuses a value that
// slipped past ingest, and counts it.
func TestExportersDropInvalidValues(t *testing.T) {
	bad := []ioc.Indicator{
		{Type: ioc.TypeIP, Value: "192.168.1.1"},
		{Type: ioc.TypeMD5, Value: "not-a-hash;rm"},
		{Type: ioc.TypeSHA256, Value: "zz"},
		{Type: ioc.TypeDomain, Value: "*.*.*"},
	}
	before := metricValue("threat_intel_export_indicators_dropped_total", "format", "suricata")
	var buf bytes.Buffer
	WriteSuricataDataset(&buf, bad, false)
	WriteSuricataDataset(&buf, bad, true)
	WriteSuricataJSONDataset(&buf, bad, "ip")
	if buf.Len() != 0 {
		t.Errorf("suricata datasets wrote invalid values: %q", buf.String())
	}
	if got := metricValue("threat_intel_export_indicators_dropped_total", "format", "suricata") - before; got != 12 {
		t.Errorf("dropped counter rose by %v, want 12", got)
	}

	buf.Reset()
	if err := WriteCSV(&buf, bad, ioc.TypeIP, ioc.TypeDomain); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != strings.Join(csvHeader, ",") {
		t.Errorf("csv wrote invalid values: %q", buf.String())
	}

	buf.Reset()
	WriteSuricataDataset(&buf, []ioc.Indicator{{Type: ioc.TypeDomain, Value: "evil.example"}}, true)
	if dec, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(buf.String())); string(dec) != "evil.example" {
		t.Errorf("valid domain lost: %q", buf.String())
	}
}

// TestAuditEmptyStoreExports documents what the handlers themselves write
// for an empty store; serving it before a set exists is prevented by the
// readiness gate in cmd/threat-intel-sync (TestExportsAnswer503UntilReady).
func TestAuditEmptyStoreExports(t *testing.T) {
	s := ioc.NewStore()
	rec := httptest.NewRecorder()
	HandleZeekIntel(s)(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Body.String(); got != "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n" {
		t.Errorf("empty zeek export = %q", got)
	}
}

func assertZeekWellFormed(t *testing.T, out string, wantRows int) []string {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines)-1 != wantRows {
		t.Errorf("intel.dat has %d indicator lines, want %d:\n%s", len(lines)-1, wantRows, out)
	}
	if !strings.HasPrefix(lines[0], "#fields\t") {
		t.Errorf("missing #fields header: %q", lines[0])
	}
	for i, l := range lines[1:] {
		if n := len(strings.Split(l, "\t")); n != 5 {
			t.Errorf("line %d has %d fields, want 5: %q", i, n, l)
		}
		if strings.ContainsAny(l, "\r\x00") {
			t.Errorf("line %d contains a control character: %q", i, l)
		}
	}
	return lines
}

// metricValue reads one series from the default registry. It stands in for
// prometheus/testutil, which would add a module dependency for tests only.
func metricValue(name string, labels ...string) float64 {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, m := range mf.GetMetric() {
			for i := 0; i+1 < len(labels); i += 2 {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == labels[i] && lp.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue next
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return 0
}
