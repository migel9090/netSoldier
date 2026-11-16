package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// arpFrame builds an Ethernet/ARP request from src claiming spa.
func arpFrame(src net.HardwareAddr, spa net.IP) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], 0x0806)
	a := f[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], 1)
	copy(a[8:14], src)
	copy(a[14:18], spa.To4())
	return f
}

func post(t *testing.T, in *Ingestor, token string, b batch) (*httptest.ResponseRecorder, []command) {
	t.Helper()
	body, _ := json.Marshal(b)
	req := httptest.NewRequest("POST", "/agent/v1/frames", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	in.Register(mux)
	mux.ServeHTTP(rec, req)
	var resp struct {
		Commands []command `json:"commands"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp.Commands
}

func TestIngestAuth(t *testing.T) {
	var got []discovery.Sighting
	hb := NewHeartbeat(time.Second, []string{"arp"})
	in := NewIngestor("tok", func(s discovery.Sighting) { got = append(got, s) }, hb, NewCommandQueue())

	if rec, _ := post(t, in, "", batch{Agent: "n"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec, _ := post(t, in, "wrong", batch{Agent: "n"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	if rec, _ := post(t, in, "tok", batch{Agent: "n"}); rec.Code != http.StatusOK {
		t.Fatalf("right token: %d", rec.Code)
	}
}

func TestIngestDispatchesToParsersWithTimeAndInterface(t *testing.T) {
	var got []discovery.Sighting
	hb := NewHeartbeat(time.Second, []string{"arp"})
	in := NewIngestor("tok", func(s discovery.Sighting) { got = append(got, s) }, hb, NewCommandQueue())

	capturedAt := time.Now().Add(-time.Second).Truncate(time.Nanosecond)
	b := batch{
		Agent:     "soc-node-1",
		Interface: "eth0",
		Frames: []frame{
			{T: capturedAt.UnixNano(), Proto: "arp", Data: arpFrame(net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.IPv4(192, 168, 1, 5))},
			{T: capturedAt.UnixNano(), Proto: "bogus", Data: []byte{1, 2, 3}},
		},
		Status: status{Capture: map[string]bool{"arp": true}, Dropped: 7},
	}
	rec, _ := post(t, in, "tok", b)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	if len(got) != 1 {
		t.Fatalf("dispatched %d sightings, want 1 (bogus proto dropped)", len(got))
	}
	s := got[0]
	if s.MAC != "02:00:00:00:00:01" || s.IP != "192.168.1.5" {
		t.Errorf("parsed sighting = %+v", s)
	}
	if !s.CapturedAt.Equal(capturedAt) {
		t.Errorf("capture time = %v, want %v", s.CapturedAt, capturedAt)
	}
	if s.Interface != "eth0" {
		t.Errorf("interface = %q", s.Interface)
	}
	// The heartbeat was recorded.
	if st := hb.Status(); !st.Ready || st.Dropped != 7 {
		t.Errorf("heartbeat not recorded: %+v", st)
	}
}

func TestIngestReturnsPendingProbes(t *testing.T) {
	q := NewCommandQueue()
	q.Probe("192.168.1.0/24")
	in := NewIngestor("tok", func(discovery.Sighting) {}, NewHeartbeat(time.Second, nil), q)
	_, cmds := post(t, in, "tok", batch{Agent: "n"})
	if len(cmds) != 1 || cmds[0].Type != "arp_probe" || cmds[0].Target != "192.168.1.0/24" {
		t.Fatalf("commands = %+v", cmds)
	}
	// Taken once, not resent.
	_, cmds = post(t, in, "tok", batch{Agent: "n"})
	if len(cmds) != 0 {
		t.Fatalf("probe resent: %+v", cmds)
	}
}

func TestBodyTooLargeRejected(t *testing.T) {
	in := NewIngestor("tok", func(discovery.Sighting) {}, NewHeartbeat(time.Second, nil), NewCommandQueue())
	big := make([]byte, maxBody+10)
	req := httptest.NewRequest("POST", "/agent/v1/frames", bytes.NewReader(big))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	in.Register(mux)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d", rec.Code)
	}
}
