package config

import (
	"strings"
	"testing"
	"time"
)

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

var base = []string{
	"NETAGENT_ID", "soc-node-1",
	"NETAGENT_INTERFACE", "eth0",
	"DEVICE_INVENTORY_URL", "http://device-inventory:8081",
	"NETAGENT_TOKEN", "t",
}

func TestMinimalConfig(t *testing.T) {
	c, err := Load(env(base...))
	if err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	if c.Isolation {
		t.Error("isolation must be off by default")
	}
	if len(c.Protocols) != 5 {
		t.Errorf("default protocols = %v", c.Protocols)
	}
	if c.Heartbeat != 3*time.Second {
		t.Errorf("heartbeat = %v", c.Heartbeat)
	}
}

func TestMissingRequiredNamesEveryProblem(t *testing.T) {
	_, err := Load(env())
	if err == nil {
		t.Fatal("empty config accepted")
	}
	for _, want := range []string{"NETAGENT_ID", "NETAGENT_INTERFACE", "DEVICE_INVENTORY_URL", "NETAGENT_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
}

func TestIsolationRequiresItsSettings(t *testing.T) {
	// Enabling isolation without the gateway or token must fail closed and
	// name what is missing.
	_, err := Load(env(append(base, "NETAGENT_ENABLE_ARP_ISOLATION", "true")...))
	if err == nil {
		t.Fatal("isolation without a gateway accepted")
	}
	for _, want := range []string{"KILLSWITCH_URL", "NETAGENT_KILLSWITCH_TOKEN", "NETAGENT_GATEWAY_IP", "NETAGENT_GATEWAY_MAC"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("isolation error does not name %s: %v", want, err)
		}
	}
}

func TestFullIsolationConfig(t *testing.T) {
	c, err := Load(env(append(base,
		"NETAGENT_ENABLE_ARP_ISOLATION", "true",
		"KILLSWITCH_URL", "http://killswitch:8084",
		"NETAGENT_KILLSWITCH_TOKEN", "k",
		"NETAGENT_GATEWAY_IP", "192.168.1.1",
		"NETAGENT_GATEWAY_MAC", "aa:bb:cc:00:00:01",
		"NETAGENT_PROTECTED_IPS", "192.168.1.53, 192.168.1.2",
		"NETAGENT_PROTECTED_MACS", "aa:bb:cc:00:00:53",
		"NETAGENT_MAX_TTL", "30m",
	)...))
	if err != nil {
		t.Fatalf("full isolation config rejected: %v", err)
	}
	if !c.Isolation || c.GatewayIP.String() != "192.168.1.1" || c.MaxTTL != 30*time.Minute {
		t.Errorf("parsed %+v", c)
	}
	if len(c.ProtectedIPs) != 2 || len(c.ProtectedMACs) != 1 {
		t.Errorf("protected lists: %+v %+v", c.ProtectedIPs, c.ProtectedMACs)
	}
}

func TestBadValuesRejected(t *testing.T) {
	bad := [][]string{
		{"NETAGENT_PROTOCOLS", "arp,wifi"},
		{"NETAGENT_HEARTBEAT", "-1s"},
		{"NETAGENT_QUEUE_DEPTH", "lots"},
		{"NETAGENT_ENABLE_ARP_PROBE", "yes"},
		{"NETAGENT_ENABLE_ARP_ISOLATION", "maybe"},
	}
	for _, kv := range bad {
		if _, err := Load(env(append(base, kv...)...)); err == nil {
			t.Errorf("%s=%s accepted", kv[0], kv[1])
		}
	}
}

func TestBadGatewayRejected(t *testing.T) {
	_, err := Load(env(append(base,
		"NETAGENT_ENABLE_ARP_ISOLATION", "true",
		"KILLSWITCH_URL", "http://k",
		"NETAGENT_KILLSWITCH_TOKEN", "k",
		"NETAGENT_GATEWAY_IP", "192.168.001.001",
		"NETAGENT_GATEWAY_MAC", "ff:ff:ff:ff:ff:ff", // broadcast, not unicast
	)...))
	if err == nil || !strings.Contains(err.Error(), "NETAGENT_GATEWAY_IP") || !strings.Contains(err.Error(), "NETAGENT_GATEWAY_MAC") {
		t.Fatalf("bad gateway not rejected clearly: %v", err)
	}
}
