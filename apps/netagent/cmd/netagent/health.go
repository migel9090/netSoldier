package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// healthCommand is the argument that runs the health check instead of the
// agent: `netagent health`.
const healthCommand = "health"

// minHealthAge is the floor of how old the health file may be before the
// check fails, so a short heartbeat does not make the probe flap on a busy
// node.
const minHealthAge = 10 * time.Second

// runHealthCheck is `netagent health`, the container's exec probe. The agent
// listens on no port, so it cannot be probed over HTTP, and its image has no
// shell to read a file with. The running agent rewrites NETAGENT_HEALTH_FILE
// every heartbeat (startHealth); the check passes when that file exists,
// parses and was written within three heartbeats (at least minHealthAge).
// It reads the same environment as the agent and opens no socket.
func runHealthCheck(getenv func(string) string, now time.Time, out io.Writer) int {
	unhealthy := func(format string, a ...any) int {
		fmt.Fprintf(out, "unhealthy: "+format+"\n", a...)
		return 1
	}
	path := strings.TrimSpace(getenv("NETAGENT_HEALTH_FILE"))
	if path == "" {
		return unhealthy("NETAGENT_HEALTH_FILE is not set, so the agent writes no health file")
	}
	heartbeat := 3 * time.Second // the agent's default (internal/config)
	if v := strings.TrimSpace(getenv("NETAGENT_HEARTBEAT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return unhealthy("NETAGENT_HEARTBEAT=%q is not a positive duration", v)
		}
		heartbeat = d
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return unhealthy("%v", err)
	}
	var h struct {
		Agent string    `json:"agent"`
		Time  time.Time `json:"time"`
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return unhealthy("%s does not parse: %v", path, err)
	}
	if h.Time.IsZero() {
		return unhealthy("%s carries no time", path)
	}
	maxAge := max(3*heartbeat, minHealthAge)
	if age := now.Sub(h.Time); age > maxAge {
		return unhealthy("%s was last written %s ago (limit %s): the agent has stopped", path,
			age.Round(time.Second), maxAge)
	}
	fmt.Fprintf(out, "healthy: agent %s, health written %s ago\n", h.Agent,
		max(now.Sub(h.Time), 0).Round(time.Millisecond))
	return 0
}

// subcommand handles the agent's command line. With no argument the agent
// runs; `health` runs the probe. Anything else is refused: a mistyped probe
// command must not start a second agent with raw network access.
func subcommand(args []string, getenv func(string) string, now func() time.Time, out, errOut io.Writer) (exit int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	if args[0] == healthCommand && len(args) == 1 {
		return runHealthCheck(getenv, now(), out), true
	}
	fmt.Fprintf(errOut, "netagent: unknown arguments %q (usage: netagent [%s])\n", args, healthCommand)
	return 2, true
}
