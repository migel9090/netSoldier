package events

import (
	"strings"
	"testing"
)

func TestParseActor(t *testing.T) {
	for _, ok := range []string{"alice", "Anna Kowalska", strings.Repeat("x", MaxActorLen), "ttl2", "~!@#"} {
		if got, err := ParseActor([]string{ok}); err != nil || got != ok {
			t.Errorf("ParseActor(%q) = %q, %v", ok, got, err)
		}
	}
	for name, values := range map[string][]string{
		"missing":         nil,
		"twice":           {"alice", "bob"},
		"empty":           {""},
		"too long":        {strings.Repeat("x", MaxActorLen+1)},
		"control char":    {"tab\there"},
		"not ASCII":       {"Michał"},
		"reserved":        {"ttl"},
		"reserved, cased": {"Auto-Policy"},
		"netagent":        {"netagent"},
		"reconcile":       {"reconcile"},
		"system":          {"SYSTEM"},
	} {
		if got, err := ParseActor(values); err == nil {
			t.Errorf("%s: ParseActor(%q) accepted %q", name, values, got)
		}
	}
	if _, err := ParseActor(nil); err == nil || !strings.Contains(err.Error(), ActorHeader) {
		t.Errorf("the refusal must name the header: %v", err)
	}
}
