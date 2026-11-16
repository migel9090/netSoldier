//go:build e2e

package e2e

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This file is the ADR-0004 end-to-end proof. The outer invocation builds the
// real netagent and device-inventory binaries and re-execs this one test
// under `unshare -Urn`, so everything below runs in a private user+network
// namespace on a veth pair — nothing touches the real LAN. Inside:
//
//   - device-inventory runs with ALL capabilities dropped (proved by reading
//     its /proc/<pid>/status) and still ends up with the emulated device in
//     its inventory;
//   - the real netagent captures the device's ARP and DHCP frames off the
//     veth and forwards them;
//   - the isolation guard refuses the audit's dangerous targets, and the
//     refusals travel back to a stub killswitch over the real poll channel.
//
// It only ever sends frames on the veth inside the namespace.

const nsInnerEnv = "NETAGENT_NS_INNER"

func TestNetagentNamespaceE2E(t *testing.T) {
	if os.Getenv(nsInnerEnv) != "" {
		runInsideNamespace(t)
		return
	}
	if testing.Short() {
		t.Skip("skipping namespace e2e in short mode")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 'ip' not available")
	}
	// A user namespace with CAP_NET_ADMIN over a fresh net namespace is what
	// the whole test needs; probe it cheaply before building anything.
	if out, err := exec.Command("unshare", "-Urn", "true").CombinedOutput(); err != nil {
		t.Skipf("unprivileged user+net namespaces unavailable: %v: %s", err, out)
	}

	root := repoRoot(t)
	agentBin := goBuild(t, root, "apps/netagent")
	invBin := goBuild(t, root, "apps/device-inventory")

	// Re-exec just this test inside the namespace. Verbose output is streamed
	// so a failure inside is readable in the outer log.
	cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestNetagentNamespaceE2E$", "-test.v")
	cmd.Env = append(os.Environ(),
		nsInnerEnv+"=1",
		"NS_AGENT_BIN="+agentBin,
		"NS_INV_BIN="+invBin,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("in-namespace run failed: %v", err)
	}
}

func runInsideNamespace(t *testing.T) {
	agentBin, invBin := os.Getenv("NS_AGENT_BIN"), os.Getenv("NS_INV_BIN")
	if agentBin == "" || invBin == "" {
		t.Fatal("inner run without binary paths")
	}

	// Network: loopback plus a veth pair. The agent captures on va; the
	// emulated device sends from vb (its peer), so frames arrive on va.
	const (
		vaName, vbName = "vinv", "vdev"
		subnet         = "192.168.50."
		agentIP        = subnet + "1"
		devIP          = subnet + "2"
	)
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", vaName, "type", "veth", "peer", "name", vbName)
	run("ip", "addr", "add", agentIP+"/24", "dev", vaName)
	run("ip", "addr", "add", devIP+"/24", "dev", vbName)
	run("ip", "link", "set", vaName, "up")
	run("ip", "link", "set", vbName, "up")

	va, err := net.InterfaceByName(vaName)
	if err != nil {
		t.Fatal(err)
	}
	vb, err := net.InterfaceByName(vbName)
	if err != nil {
		t.Fatal(err)
	}
	devMAC := vb.HardwareAddr

	// Stub killswitch: the real poll channel (contract 8.2). It hands the
	// agent isolate commands for the audit's dangerous targets and records
	// the refusals that come back.
	ks := newStubKillswitch()
	ksSrv := httptest.NewServer(ks)
	defer ksSrv.Close()

	const invAddr = "127.0.0.1:18081"
	const token = "ns-agent-token"
	const apiKey = "ns-api-key"
	const ksToken = "ns-ks-token"

	// device-inventory, with EVERY capability dropped. setpriv needs
	// CAP_SETPCAP, which root-in-userns has; the dropped child does not, and
	// we read its /proc status below to prove the effective set is empty.
	invArgs := []string{
		"setpriv", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
		invBin,
	}
	invCmd := exec.Command(invArgs[0], invArgs[1:]...)
	invCmd.Env = append(os.Environ(),
		"LISTEN_ADDR="+invAddr,
		"DB_PATH="+t.TempDir()+"/devices.db",
		"DEVICE_API_KEY="+apiKey,
		"NETAGENT_TOKEN="+token,
		"NETAGENT_EXPECT_CAPTURE=arp,dhcp",
		"NETAGENT_HEARTBEAT_TIMEOUT=10s",
	)
	invCmd.Stdout, invCmd.Stderr = os.Stderr, os.Stderr
	if err := invCmd.Start(); err != nil {
		t.Fatalf("start device-inventory: %v", err)
	}
	defer func() { _ = invCmd.Process.Kill(); _ = invCmd.Wait() }()

	waitHealthy(t, "http://"+invAddr+"/healthz")
	assertEmptyCaps(t, invCmd.Process.Pid)

	// netagent, capturing on va and forwarding to device-inventory, with
	// isolation enabled and the gateway pinned.
	agentCmd := exec.Command(agentBin)
	agentCmd.Env = append(os.Environ(),
		"NETAGENT_ID=ns-agent",
		"NETAGENT_INTERFACE="+vaName,
		"DEVICE_INVENTORY_URL=http://"+invAddr+"/agent/v1/frames",
		"NETAGENT_TOKEN="+token,
		"NETAGENT_PROTOCOLS=arp,dhcp",
		"NETAGENT_HEARTBEAT=500ms",
		"NETAGENT_ENABLE_ARP_ISOLATION=true",
		"KILLSWITCH_URL="+ksSrv.URL+"/agent/v1/poll",
		"NETAGENT_KILLSWITCH_TOKEN="+ksToken,
		"NETAGENT_POLL_INTERVAL=300ms",
		"NETAGENT_GATEWAY_IP="+subnet+"254",
		"NETAGENT_GATEWAY_MAC=02:00:00:00:fe:fe",
		"NETAGENT_MAX_TTL=1h",
	)
	agentCmd.Stdout, agentCmd.Stderr = os.Stderr, os.Stderr
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("start netagent: %v", err)
	}
	defer func() { _ = agentCmd.Process.Kill(); _ = agentCmd.Wait() }()

	// Wait for the agent to come up (device-inventory /readyz needs its
	// heartbeat with arp and dhcp up).
	waitReady(t, "http://"+invAddr+"/readyz")

	// Emulate the device: send its ARP announcement and a DHCP request from
	// vb, repeatedly, until device-inventory records it. The agent on va
	// captures them and forwards them.
	stopSender := make(chan struct{})
	go func() {
		tick := time.NewTicker(300 * time.Millisecond)
		defer tick.Stop()
		for {
			sendFrame(t, vb.Index, buildARPReply(devMAC, va.HardwareAddr, net.ParseIP(devIP), net.ParseIP(agentIP)))
			sendFrame(t, vb.Index, buildDHCPRequest(devMAC, net.ParseIP(devIP), "lab-phone"))
			select {
			case <-stopSender:
				return
			case <-tick.C:
			}
		}
	}()

	dev := waitForDevice(t, "http://"+invAddr, apiKey, strings.ToLower(devMAC.String()))
	close(stopSender)
	if dev.IP != devIP {
		t.Errorf("device IP = %q, want %q", dev.IP, devIP)
	}
	if dev.Hostname != "lab-phone" {
		t.Errorf("device hostname = %q, want lab-phone", dev.Hostname)
	}
	t.Logf("device-inventory (no capabilities) learned %s -> %s (%q) from the agent's captures",
		dev.MAC, dev.IP, dev.Hostname)

	// Isolation refusals: queue the audit's dangerous targets and confirm the
	// agent refuses each and reports why over the real poll channel.
	ks.queue(
		ksCmd{ID: "i-bcast", Type: "arp_isolate", MAC: "ff:ff:ff:ff:ff:ff", IP: subnet + "77", TTL: 600},
		ksCmd{ID: "i-mcast", Type: "arp_isolate", MAC: "11:22:33:44:55:66", IP: subnet + "77", TTL: 600},
		ksCmd{ID: "i-gw", Type: "arp_isolate", MAC: "02:00:00:00:aa:aa", IP: subnet + "254", TTL: 600},
		ksCmd{ID: "i-off", Type: "arp_isolate", MAC: "02:00:00:00:aa:bb", IP: "10.0.0.9", TTL: 600},
		ksCmd{ID: "i-self", Type: "arp_isolate", MAC: "02:00:00:00:aa:cc", IP: agentIP, TTL: 600},
	)
	for _, id := range []string{"i-bcast", "i-mcast", "i-gw", "i-off", "i-self"} {
		r := ks.awaitResult(t, id, 5*time.Second)
		if r.OK || !strings.HasPrefix(r.Error, "refused:") {
			t.Errorf("command %s: want a refusal, got %+v", id, r)
		} else {
			t.Logf("isolation %s correctly refused: %s", id, r.Error)
		}
	}
}

// assertEmptyCaps reads /proc/<pid>/status and fails unless the effective,
// permitted and bounding capability sets are all empty.
func assertEmptyCaps(t *testing.T, pid int) {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatalf("read proc status: %v", err)
	}
	want := map[string]bool{"CapEff": true, "CapPrm": true, "CapBnd": true, "CapInh": true}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || !want[k] {
			continue
		}
		seen[k] = true
		if strings.TrimSpace(v) != "0000000000000000" {
			t.Fatalf("device-inventory %s = %s, want empty — it must run with no capabilities", k, strings.TrimSpace(v))
		}
	}
	for k := range want {
		if !seen[k] {
			t.Fatalf("capability line %s missing from proc status", k)
		}
	}
	t.Log("device-inventory effective/permitted/bounding capability sets are all empty")
}

type nsDevice struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

func waitForDevice(t *testing.T, base, apiKey, mac string) nsDevice {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last []nsDevice
	for time.Now().Before(deadline) {
		var devices []nsDevice
		httpGetJSONBearer(t, base+"/devices", apiKey, &devices)
		last = devices
		for _, d := range devices {
			if d.MAC == mac && d.IP != "" {
				return d
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("device %s never appeared in the inventory; last = %+v", mac, last)
	return nsDevice{}
}

func waitReady(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("never ready: %s", url)
}

// sendFrame transmits one Ethernet frame out of the interface with index
// ifindex, inside the namespace, on the veth.
func sendFrame(t *testing.T, ifindex int, frame []byte) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open send socket: %v", err)
	}
	defer unix.Close(fd)
	addr := unix.SockaddrLinklayer{Protocol: htonsTest(binary.BigEndian.Uint16(frame[12:14])), Ifindex: ifindex, Halen: 6}
	copy(addr.Addr[:6], frame[0:6])
	if err := unix.Sendto(fd, frame, 0, &addr); err != nil {
		t.Fatalf("send frame: %v", err)
	}
}

func htonsTest(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// buildARPReply builds an Ethernet/ARP reply announcing spa at sha.
func buildARPReply(sha, tha net.HardwareAddr, spa, tpa net.IP) []byte {
	f := make([]byte, 42)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], sha)
	binary.BigEndian.PutUint16(f[12:14], 0x0806)
	a := f[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], 2) // reply
	copy(a[8:14], sha)
	copy(a[14:18], spa.To4())
	copy(a[18:24], tha)
	copy(a[24:28], tpa.To4())
	return f
}

// buildDHCPRequest builds an Ethernet/IPv4/UDP DHCP REQUEST from chaddr for
// requestedIP, naming the host. Checksums are left zero: device-inventory
// does not verify them.
func buildDHCPRequest(chaddr net.HardwareAddr, requestedIP net.IP, host string) []byte {
	bootp := make([]byte, 240)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6 // op BOOTREQUEST, htype Ethernet, hlen 6
	copy(bootp[28:34], chaddr)
	binary.BigEndian.PutUint32(bootp[236:240], 0x63825363) // magic cookie
	opts := []byte{53, 1, 3}                               // option 53 = REQUEST
	opts = append(opts, 50, 4)
	opts = append(opts, requestedIP.To4()...)
	opts = append(opts, 12, byte(len(host)))
	opts = append(opts, host...)
	opts = append(opts, 55, 3, 1, 3, 6)
	opts = append(opts, 255) // end
	payload := append(bootp, opts...)

	ihl, ulen := 20, 8+len(payload)
	f := make([]byte, 14+ihl+ulen)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], chaddr)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	total := ihl + ulen
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64 // TTL
	ip[9] = 17 // UDP
	copy(ip[12:16], net.IPv4zero.To4())
	copy(ip[16:20], net.IPv4bcast.To4())
	udp := ip[ihl:]
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], 67)
	binary.BigEndian.PutUint16(udp[4:6], uint16(ulen))
	copy(udp[8:], payload)
	return f
}

// stubKillswitch is the agent's POST /agent/v1/poll peer for the test.
type ksCmd struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	MAC  string `json:"mac,omitempty"`
	IP   string `json:"ip,omitempty"`
	TTL  int64  `json:"ttl_seconds,omitempty"`
}

type ksResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type stubKillswitch struct {
	mu      sync.Mutex
	pending []ksCmd
	results map[string]ksResult
}

func newStubKillswitch() *stubKillswitch {
	return &stubKillswitch{results: map[string]ksResult{}}
}

func (s *stubKillswitch) queue(cmds ...ksCmd) {
	s.mu.Lock()
	s.pending = append(s.pending, cmds...)
	s.mu.Unlock()
}

func (s *stubKillswitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Results []ksResult `json:"results"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	s.mu.Lock()
	for _, res := range body.Results {
		s.results[res.ID] = res
	}
	out := s.pending
	s.pending = nil
	s.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"commands": out})
}

func (s *stubKillswitch) awaitResult(t *testing.T, id string, d time.Duration) ksResult {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		r, ok := s.results[id]
		s.mu.Unlock()
		if ok {
			return r
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no result for command %s within %s", id, d)
	return ksResult{}
}
