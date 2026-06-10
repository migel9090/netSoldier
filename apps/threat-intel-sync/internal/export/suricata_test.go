package export

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

func TestWriteSuricataDatasetBase64(t *testing.T) {
	indicators := []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "evil.example.com"},
		{Type: ioc.TypeDomain, Value: "bad.example.net"},
	}

	var buf bytes.Buffer
	WriteSuricataDataset(&buf, indicators, true)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	// Sorted by raw value: bad.example.net before evil.example.com.
	want := base64.StdEncoding.EncodeToString([]byte("bad.example.net"))
	if lines[0] != want {
		t.Errorf("line 0: want %q, got %q", want, lines[0])
	}
	for i, line := range lines {
		decoded, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			t.Errorf("line %d is not valid base64: %v", i, err)
		}
		if strings.Contains(string(decoded), "\n") {
			t.Errorf("line %d decodes to multi-line value", i)
		}
	}
}

func TestWriteSuricataDatasetRaw(t *testing.T) {
	indicators := []ioc.Indicator{
		{Type: ioc.TypeIP, Value: "198.51.100.7"},
		{Type: ioc.TypeIP, Value: "192.0.2.1"},
	}

	var buf bytes.Buffer
	WriteSuricataDataset(&buf, indicators, false)

	if got := buf.String(); got != "192.0.2.1\n198.51.100.7\n" {
		t.Errorf("unexpected output: %q", got)
	}
}

func TestWriteSuricataJSONDataset(t *testing.T) {
	indicators := []ioc.Indicator{
		{
			Type: ioc.TypeDomain, Value: "evil.example.com",
			Source: "threatfox", Threat: "Cobalt Strike C2",
			Confidence: 90, Tags: []string{"mitre-attack:T1071"},
		},
		{Type: ioc.TypeDomain, Value: "bad.example.net", Source: "urlhaus", Confidence: 60},
	}

	var buf bytes.Buffer
	WriteSuricataJSONDataset(&buf, indicators, "domain")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 is not valid JSON: %v", err)
	}
	// Sorted by value: bad.example.net first.
	if first["domain"] != "bad.example.net" {
		t.Errorf("domain: want bad.example.net, got %v", first["domain"])
	}
	if first["severity"] != "medium" {
		t.Errorf("severity: want medium, got %v", first["severity"])
	}
	if _, ok := first["threat"]; ok {
		t.Error("threat should be omitted when empty")
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v", err)
	}
	if second["severity"] != "high" {
		t.Errorf("severity: want high, got %v", second["severity"])
	}
	if second["threat"] != "Cobalt Strike C2" {
		t.Errorf("threat: want Cobalt Strike C2, got %v", second["threat"])
	}
}

func TestSuricataIPDatasetsExcludeCIDR(t *testing.T) {
	store := ioc.NewStore()
	store.UpsertAll([]ioc.Indicator{
		{Type: ioc.TypeIP, Value: "198.51.100.7", Source: "feodo", Confidence: 85},
		{Type: ioc.TypeIP, Value: "192.0.2.0/24", Source: "spamhaus", Confidence: 70},
		{Type: ioc.TypeIP, Value: "2001:db8::1", Source: "misp", Confidence: 50},
	})

	// Suricata ip datasets reject CIDR ranges: one bad line fails the
	// whole dataset load, so CIDRs must never reach either format.
	rec := httptest.NewRecorder()
	HandleSuricataDataset(store, false, ioc.TypeIP)(rec, httptest.NewRequest("GET", "/", nil))
	if body := rec.Body.String(); strings.Contains(body, "/24") {
		t.Errorf("lst dataset contains CIDR: %q", body)
	} else if !strings.Contains(body, "198.51.100.7") || !strings.Contains(body, "2001:db8::1") {
		t.Errorf("lst dataset missing exact IPs: %q", body)
	}

	rec = httptest.NewRecorder()
	HandleSuricataJSONDataset(store, "ip", ioc.TypeIP)(rec, httptest.NewRequest("GET", "/", nil))
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	// 2 exact IPs + the never-empty sentinel entry.
	if len(lines) != 3 {
		t.Fatalf("expected 3 json lines, got %d: %q", len(lines), rec.Body.String())
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid json line %q: %v", line, err)
		}
		if ip, _ := entry["ip"].(string); strings.Contains(ip, "/") {
			t.Errorf("json dataset contains CIDR: %v", entry["ip"])
		}
	}
}

func TestSuricataJSONDatasetNeverEmpty(t *testing.T) {
	store := ioc.NewStore()

	for _, tc := range []struct{ valueKey, sentinel string }{
		{"domain", "sentinel.netsoldier.invalid"},
		{"ip", "192.0.2.254"},
	} {
		rec := httptest.NewRecorder()
		HandleSuricataJSONDataset(store, tc.valueKey, ioc.TypeDomain)(rec, httptest.NewRequest("GET", "/", nil))

		var entry map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
			t.Fatalf("%s: expected single sentinel line, got %q", tc.valueKey, rec.Body.String())
		}
		if entry[tc.valueKey] != tc.sentinel {
			t.Errorf("%s: want sentinel %q, got %v", tc.valueKey, tc.sentinel, entry[tc.valueKey])
		}
	}
}
