package events

import "time"

// EnforcementSchemaVersion is the current version of the EnforcementAction schema.
const EnforcementSchemaVersion = "1.0"

// Enforcement action types.
const (
	ActionDNSSinkhole = "dns_sinkhole"
	ActionARPIsolate  = "arp_isolate"
	ActionSwitchACL   = "switch_acl"
)

// Enforcement states.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateActive   = "active"
	StateReverted = "reverted"
	StateRejected = "rejected"
)

// EnforcementAction represents a killswitch enforcement decision and its
// lifecycle. Used by killswitch-controller, web-ui (approval flow), and
// the append-only audit log in ClickHouse.
type EnforcementAction struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`

	// What triggered this action.
	DetectionID string `json:"detection_id"`

	// Enforcement details.
	ActionType    string `json:"action_type"` // ActionDNSSinkhole, ActionARPIsolate, ActionSwitchACL
	State         string `json:"state"`       // StatePending..StateRejected
	TargetMAC     string `json:"target_mac"`
	TargetIP      string `json:"target_ip,omitempty"`
	BlockedDomain string `json:"blocked_domain,omitempty"` // for dns_sinkhole

	// Policy.
	PolicyRule   string `json:"policy_rule"`
	AutoApproved bool   `json:"auto_approved"`

	// Timing.
	TTLSeconds int        `json:"ttl_seconds,omitempty"` // auto-revert after N seconds
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevertedAt *time.Time `json:"reverted_at,omitempty"`

	// Audit.
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
}
