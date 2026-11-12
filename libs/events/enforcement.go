package events

import "time"

// EnforcementSchemaVersion is the current version of the EnforcementAction schema.
//
// 2.0 splits the single failure state into apply_failed and revert_failed,
// adds expired, and carries the detection's summary and device name so the
// approval dialog can show what is being approved without a second lookup.
const EnforcementSchemaVersion = "2.0"

// Enforcement action types.
const (
	ActionDNSSinkhole = "dns_sinkhole"
	ActionARPIsolate  = "arp_isolate"
	ActionSwitchACL   = "switch_acl"
)

// actionTypes is the closed action-type vocabulary, mirrored by the schema.
var actionTypes = []string{ActionDNSSinkhole, ActionARPIsolate, ActionSwitchACL}

// Enforcement states.
//
// A failure is never collapsed into "reverted" or "active": an action whose
// driver failed to apply is NOT enforced, and one whose driver failed to
// revert IS still enforced. Telling the operator the device is free when it
// is not is the one lie a killswitch must never tell, and the two failures
// call for opposite responses — so they are two states.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateActive   = "active"
	StateReverted = "reverted"
	StateRejected = "rejected"
	// StateExpired is a pending action nobody approved in time.
	StateExpired = "expired"
	// StateApplyFailed means the driver failed to apply: nothing is
	// enforced. Terminal.
	StateApplyFailed = "apply_failed"
	// StateRevertFailed means the driver failed to lift the enforcement: it
	// IS still enforced. The TTL reaper keeps retrying; such an action is
	// never evicted and never reported as reverted.
	StateRevertFailed = "revert_failed"

	// StateFailed is the single failure state of schema 1.x.
	//
	// Deprecated: it cannot say whether the device is still enforced. Use
	// StateApplyFailed or StateRevertFailed. Kept until the store's state
	// machine moves to the split states.
	StateFailed = "failed"
)

// enforcementStates is every state an action can be seen in on the wire,
// mirrored by the schema enum. StateFailed stays listed for as long as the
// controller can still emit it.
var enforcementStates = []string{
	StatePending, StateApproved, StateActive, StateReverted, StateRejected,
	StateExpired, StateApplyFailed, StateRevertFailed, StateFailed,
}

// EnforcementAction represents a killswitch enforcement decision and its
// lifecycle. Used by killswitch-controller, web-ui (approval flow), and
// the append-only audit log in ClickHouse.
type EnforcementAction struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`

	// What triggered this action.
	DetectionID string `json:"detection_id"`
	// DetectionSummary is the triggering event's summary, for the approval
	// dialog. Display only, like the summary it copies.
	DetectionSummary string `json:"detection_summary,omitempty"`
	// ClientName is the device name the detection carried, if known.
	ClientName string `json:"client_name,omitempty"`

	// Enforcement details.
	ActionType    string `json:"action_type"` // ActionDNSSinkhole, ActionARPIsolate, ActionSwitchACL
	State         string `json:"state"`       // one of enforcementStates
	TargetMAC     string `json:"target_mac"`
	TargetIP      string `json:"target_ip,omitempty"`
	BlockedDomain string `json:"blocked_domain,omitempty"` // for dns_sinkhole; from a domain target only

	// Policy.
	PolicyRule   string `json:"policy_rule"`
	AutoApproved bool   `json:"auto_approved"`

	// Timing.
	TTLSeconds int `json:"ttl_seconds,omitempty"` // auto-revert after N seconds
	// ActivatedAt is when the driver confirmed the apply.
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevertedAt  *time.Time `json:"reverted_at,omitempty"`

	// Audit: who drove each human transition ("ttl" for the reaper).
	ApprovedBy string `json:"approved_by,omitempty"`
	RejectedBy string `json:"rejected_by,omitempty"`
	RevertedBy string `json:"reverted_by,omitempty"`
	Reason     string `json:"reason,omitempty"`

	// FailureReason explains a failed action: which driver call failed and
	// why, so the UI can show "approved but not enforced" (or "still
	// enforced") rather than leaving the operator to infer it from pod logs.
	FailureReason string `json:"failure_reason,omitempty"`
}
