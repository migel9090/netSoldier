package agent

import "testing"

func TestCommandQueueCoalescesAndClears(t *testing.T) {
	q := NewCommandQueue()
	q.Probe("192.168.1.0/24")
	q.Probe("192.168.1.0/24") // same target coalesces
	q.Probe("10.0.0.0/24")
	cmds := q.Take()
	if len(cmds) != 2 {
		t.Fatalf("want 2 distinct targets, got %d: %+v", len(cmds), cmds)
	}
	for _, c := range cmds {
		if c.Type != "arp_probe" || c.ID == "" {
			t.Errorf("bad command %+v", c)
		}
	}
	if again := q.Take(); len(again) != 0 {
		t.Fatalf("queue not cleared: %+v", again)
	}
}

func TestValidateProbeSubnet(t *testing.T) {
	good := []string{"192.168.1.0/24", "10.1.0.0/16", "192.0.2.0/30"}
	for _, s := range good {
		if err := ValidateProbeSubnet(s); err != nil {
			t.Errorf("ValidateProbeSubnet(%q): %v", s, err)
		}
	}
	bad := []string{"10.0.0.0/8", "garbage", "fd00::/64", "192.168.1.1", ""}
	for _, s := range bad {
		if err := ValidateProbeSubnet(s); err == nil {
			t.Errorf("ValidateProbeSubnet(%q) accepted", s)
		}
	}
}
