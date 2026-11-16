// Package config reads and validates the agent's environment. It fails
// closed: a missing or malformed setting is a start-up error naming the
// setting, never a silent default that would leave the agent half-configured
// with raw network access.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/capture"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// Config is the validated configuration.
type Config struct {
	Agent     string
	Interface string
	Protocols []string

	InventoryURL   string
	InventoryToken string
	Heartbeat      time.Duration

	QueueDepth int
	ResultsCap int

	ProbeEnabled bool
	ProbeRate    int
	ProbePace    time.Duration

	HealthFile string

	// Isolation. Off unless Isolation is true; the rest is required only then.
	Isolation        bool
	KillswitchURL    string
	KillswitchToken  string
	PollInterval     time.Duration
	GatewayIP        netip.Addr
	GatewayMAC       wire.MAC
	ProtectedMACs    map[wire.MAC]bool
	ProtectedIPs     map[netip.Addr]bool
	MaxIsolations    int
	MaxTTL           time.Duration
	IsolationsPerMin int
}

// Load reads every setting from getenv and validates it. It returns all the
// problems at once so an operator fixes them in one pass.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	req := func(key string) string {
		v := strings.TrimSpace(getenv(key))
		if v == "" {
			fail("%s is required", key)
		}
		return v
	}
	c := Config{
		Agent:          req("NETAGENT_ID"),
		Interface:      req("NETAGENT_INTERFACE"),
		InventoryURL:   req("DEVICE_INVENTORY_URL"),
		InventoryToken: req("NETAGENT_TOKEN"),
		HealthFile:     strings.TrimSpace(getenv("NETAGENT_HEALTH_FILE")),
		ProtectedMACs:  map[wire.MAC]bool{},
		ProtectedIPs:   map[netip.Addr]bool{},
	}

	c.Protocols = parseProtocols(getenv("NETAGENT_PROTOCOLS"), fail)
	c.Heartbeat = duration(getenv, "NETAGENT_HEARTBEAT", 3*time.Second, fail)
	c.QueueDepth = positive(getenv, "NETAGENT_QUEUE_DEPTH", 20000, fail)
	c.ResultsCap = positive(getenv, "NETAGENT_RESULTS_CAP", 256, fail)
	c.ProbeEnabled = boolean(getenv, "NETAGENT_ENABLE_ARP_PROBE", false, fail)
	c.ProbeRate = positive(getenv, "NETAGENT_PROBE_RATE_PER_MIN", 2, fail)
	c.ProbePace = duration(getenv, "NETAGENT_PROBE_PACE", 10*time.Millisecond, fail)

	c.Isolation = boolean(getenv, "NETAGENT_ENABLE_ARP_ISOLATION", false, fail)
	if c.Isolation {
		c.KillswitchURL = req("KILLSWITCH_URL")
		c.KillswitchToken = req("NETAGENT_KILLSWITCH_TOKEN")
		c.PollInterval = duration(getenv, "NETAGENT_POLL_INTERVAL", time.Second, fail)
		c.MaxIsolations = positive(getenv, "NETAGENT_MAX_ISOLATIONS", 8, fail)
		c.MaxTTL = duration(getenv, "NETAGENT_MAX_TTL", 2*time.Hour, fail)
		c.IsolationsPerMin = positive(getenv, "NETAGENT_ISOLATIONS_PER_MIN", 10, fail)

		if ip := req("NETAGENT_GATEWAY_IP"); ip != "" {
			a, err := wire.ParseIPv4(ip)
			if err != nil {
				fail("NETAGENT_GATEWAY_IP: %v", err)
			} else {
				c.GatewayIP = a
			}
		}
		if mac := req("NETAGENT_GATEWAY_MAC"); mac != "" {
			m, err := wire.ParseMAC(mac)
			if err != nil {
				fail("NETAGENT_GATEWAY_MAC: %v", err)
			} else if !m.Unicast() {
				fail("NETAGENT_GATEWAY_MAC: %s is not a unicast address", mac)
			} else {
				c.GatewayMAC = m
			}
		}
		parseProtected(getenv("NETAGENT_PROTECTED_MACS"), getenv("NETAGENT_PROTECTED_IPS"), &c, fail)
	}

	return c, errors.Join(errs...)
}

func parseProtocols(v string, fail func(string, ...any)) []string {
	if strings.TrimSpace(v) == "" {
		return capture.Names()
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "" || seen[name]:
		case func() bool { _, ok := capture.Lookup(name); return !ok }():
			fail("NETAGENT_PROTOCOLS: unknown protocol %q (known: %s)", name, strings.Join(capture.Names(), ","))
		default:
			seen[name] = true
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		fail("NETAGENT_PROTOCOLS: no protocol selected")
	}
	return out
}

func parseProtected(macs, ips string, c *Config, fail func(string, ...any)) {
	for _, s := range splitList(macs) {
		if m, err := wire.ParseMAC(s); err != nil {
			fail("NETAGENT_PROTECTED_MACS: %v", err)
		} else {
			c.ProtectedMACs[m] = true
		}
	}
	for _, s := range splitList(ips) {
		if a, err := wire.ParseIPv4(s); err != nil {
			fail("NETAGENT_PROTECTED_IPS: %v", err)
		} else {
			c.ProtectedIPs[a] = true
		}
	}
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func duration(getenv func(string) string, key string, def time.Duration, fail func(string, ...any)) time.Duration {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		fail("%s=%q: want a positive duration", key, v)
		return def
	}
	return d
}

func positive(getenv func(string) string, key string, def int, fail func(string, ...any)) int {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		fail("%s=%q: want a positive integer", key, v)
		return def
	}
	return n
}

func boolean(getenv func(string) string, key string, def bool, fail func(string, ...any)) bool {
	switch strings.ToLower(strings.TrimSpace(getenv(key))) {
	case "":
		return def
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		fail("%s=%q: want true or false", key, getenv(key))
		return def
	}
}
