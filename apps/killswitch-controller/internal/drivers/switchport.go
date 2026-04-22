package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// SwitchPortDriver enforces at the managed-switch level by calling
// a webhook that handles the vendor-specific interaction (SNMP, SSH,
// or REST). This decouples the killswitch logic from switch vendor
// details — the webhook handler is a swap-in adapter for any make.
//
// Operations supported by the webhook:
//
//	disable_port    — administratively shut down the switch port
//	quarantine_vlan — move the port to an isolated VLAN
//	restore         — re-enable port / restore original VLAN
//
// The webhook receives a SwitchRequest JSON body and must return 2xx
// on success or a non-2xx error with a message body.
type SwitchPortDriver struct {
	webhookURL    string
	quarantineVLAN int
	http          *http.Client
}

// SwitchRequest is the JSON body sent to the switch webhook on
// apply and revert.
type SwitchRequest struct {
	ActionID       string `json:"action_id"`
	Operation      string `json:"operation"` // "disable_port", "quarantine_vlan", "restore"
	TargetMAC      string `json:"target_mac"`
	TargetIP       string `json:"target_ip"`
	QuarantineVLAN int    `json:"quarantine_vlan,omitempty"`
}

// NewSwitchPortDriver creates a driver that delegates switch operations
// to a webhook. quarantineVLAN is the VLAN ID used for quarantine
// (0 = disable port instead of VLAN reassignment).
func NewSwitchPortDriver(webhookURL string, quarantineVLAN int) *SwitchPortDriver {
	return &SwitchPortDriver{
		webhookURL:     webhookURL,
		quarantineVLAN: quarantineVLAN,
		http:           &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *SwitchPortDriver) Name() string { return "switch_acl" }

// Apply calls the switch webhook to disable the port or move the
// device to the quarantine VLAN.
func (d *SwitchPortDriver) Apply(ctx context.Context, action *events.EnforcementAction) error {
	op := "disable_port"
	if d.quarantineVLAN > 0 {
		op = "quarantine_vlan"
	}

	req := SwitchRequest{
		ActionID:       action.ID,
		Operation:      op,
		TargetMAC:      action.TargetMAC,
		TargetIP:       action.TargetIP,
		QuarantineVLAN: d.quarantineVLAN,
	}

	if err := d.call(ctx, req); err != nil {
		return fmt.Errorf("switch apply: %w", err)
	}

	slog.Info("switch enforcement applied",
		"action_id", action.ID,
		"operation", op,
		"target_mac", action.TargetMAC,
	)
	return nil
}

// Revert calls the switch webhook to restore the port or original VLAN.
func (d *SwitchPortDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	req := SwitchRequest{
		ActionID:  action.ID,
		Operation: "restore",
		TargetMAC: action.TargetMAC,
		TargetIP:  action.TargetIP,
	}

	if err := d.call(ctx, req); err != nil {
		return fmt.Errorf("switch revert: %w", err)
	}

	slog.Info("switch enforcement reverted",
		"action_id", action.ID,
		"target_mac", action.TargetMAC,
	)
	return nil
}

func (d *SwitchPortDriver) call(ctx context.Context, sr SwitchRequest) error {
	body, err := json.Marshal(sr)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("webhook %d: %s", resp.StatusCode, errBody)
}
