package export

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

func TestWriteCSV(t *testing.T) {
	indicators := []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "evil.example.com", Source: "threatfox", Threat: "Mozi", Confidence: 90},
		{Type: ioc.TypeIP, Value: "203.0.113.7", Source: "spamhaus-drop", Confidence: 75},
		{Type: ioc.TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop"}, // CIDR: dropped
		{Type: ioc.TypeJA3, Value: "db8a6f4f9f8195ea17db377175d2cb08"},        // unrequested type
		{Type: ioc.TypeDomain, Value: `quoted,"tricky".example.com`, Source: "misp"},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, indicators, ioc.TypeDomain, ioc.TypeIP); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("re-parse csv: %v", err)
	}

	if got, want := strings.Join(rows[0], ","), "value,type,source,threat,confidence"; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	// CIDR and JA3 dropped: 3 data rows, sorted by value
	if got, want := len(rows)-1, 3; got != want {
		t.Fatalf("expected %d data rows, got %d: %v", want, got, rows[1:])
	}
	if rows[1][0] != "203.0.113.7" || rows[1][2] != "spamhaus-drop" || rows[1][4] != "75" {
		t.Errorf("row[1] = %v", rows[1])
	}
	if rows[2][0] != "evil.example.com" || rows[2][3] != "Mozi" || rows[2][4] != "90" {
		t.Errorf("row[2] = %v", rows[2])
	}
	if rows[3][0] != `quoted,"tricky".example.com` {
		t.Errorf("quoted value survived incorrectly: %v", rows[3])
	}
}

func TestWriteCSVEmptyStore(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, nil, ioc.TypeDomain, ioc.TypeIP); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	if got, want := strings.TrimRight(buf.String(), "\n"), "value,type,source,threat,confidence"; got != want {
		t.Fatalf("empty store output = %q, want header only %q", got, want)
	}
}
