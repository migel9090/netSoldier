package events

import (
	"fmt"
	"strings"
)

// ActorHeader names the operator behind a request to an operator endpoint
// (the killswitch's approve, reject and revert; the detection-engine's
// verdicts and lifts). The web UI's proxy sets it from the signed-in session
// and never forwards a client's value (contract §7). It is the only channel:
// identity fields in request bodies are not read, so a caller cannot put
// someone else's name on a decision.
const ActorHeader = "X-Netsoldier-Actor"

// MaxActorLen is the longest operator name, what the web UI accepts at
// sign-in.
const MaxActorLen = 64

// The names the services record their own decisions under. No operator may
// act under one: an operator called "ttl" would make a manual revert look
// like the reaper's.
const (
	ActorPolicy    = "auto-policy" // the killswitch policy: creations and automatic approvals
	ActorTTL       = "ttl"         // the killswitch reaper: expiries, TTL reverts, retries
	ActorReconcile = "reconcile"   // reconciliation with what is really in force
	ActorAgent     = "netagent"    // a result reported by the netagent
	ActorSystem    = "system"      // capacity eviction
)

// IsReservedActor reports whether name, in any letter case, is one of the
// services' own names.
func IsReservedActor(name string) bool {
	switch strings.ToLower(name) {
	case ActorPolicy, ActorTTL, ActorReconcile, ActorAgent, ActorSystem:
		return true
	}
	return false
}

// ParseActor returns the operator named by a request's ActorHeader values
// (http.Header.Values). The header must be there exactly once, hold 1-64
// printable ASCII characters, and not be a reserved name; otherwise the
// request is refused with the error, never attributed to a default.
func ParseActor(values []string) (string, error) {
	if len(values) != 1 {
		return "", fmt.Errorf("exactly one %s header naming the operator is required", ActorHeader)
	}
	a := values[0]
	if len(a) < 1 || len(a) > MaxActorLen {
		return "", fmt.Errorf("%s must be 1-%d characters", ActorHeader, MaxActorLen)
	}
	for i := 0; i < len(a); i++ {
		if a[i] < 0x20 || a[i] > 0x7e {
			return "", fmt.Errorf("%s must be printable ASCII", ActorHeader)
		}
	}
	if IsReservedActor(a) {
		return "", fmt.Errorf("%s %q is reserved for the controller itself", ActorHeader, a)
	}
	return a, nil
}
