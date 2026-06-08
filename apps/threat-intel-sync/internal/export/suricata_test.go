package export

import (
	"bytes"
	"encoding/base64"
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
		{Type: ioc.TypeIP, Value: "192.0.2.0/24"},
	}

	var buf bytes.Buffer
	WriteSuricataDataset(&buf, indicators, false)

	if got := buf.String(); got != "192.0.2.0/24\n198.51.100.7\n" {
		t.Errorf("unexpected output: %q", got)
	}
}
