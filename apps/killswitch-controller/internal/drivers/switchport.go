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
	webhookURL     string
	quarantineVLAN int
	secret         string
	guard          *TargetGuard
	http           *http.Client
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
//
// secret signs each request with HMAC-SHA256 over a timestamp and the body
// (events.SignatureHeader, "t=…,v1=…") so the webhook handler can verify the
// instruction came from this controller, and came from it recently.
// Disabling a switch port is the most destructive action in the system;
// sending it unauthenticated meant anyone able to reach the webhook URL could
// cut off any device, and a body-only signature meant anyone who once
// captured a "disable_port" could replay it forever. The adapter must verify
// with events.SignatureVerifier (or the same construction) and reject stale
// timestamps.
func NewSwitchPortDriver(webhookURL string, quarantineVLAN int, secret string,
	guard *TargetGuard) *SwitchPortDriver {
	return &SwitchPortDriver{
		webhookURL:     webhookURL,
		quarantineVLAN: quarantineVLAN,
		secret:         secret,
		guard:          guard,
		http:           &http.Client{Timeout: 30 * time.Second},
	}
}

func (d *SwitchPortDriver) Name() string { return "switch_acl" }

// Apply calls the switch webhook to disable the port or move the
// device to the quarantine VLAN.
//
// The request carries the identifiers in the form the guard checked them,
// not as the action spelled them: an adapter that parsed a raw string
// differently from the guard could act on a device the guard never saw.
func (d *SwitchPortDriver) Apply(ctx context.Context, action *events.EnforcementAction) error {
	dev, err := d.guard.Vet(action.TargetMAC, action.TargetIP)
	if err != nil {
		return NotApplied(err)
	}

	op := "disable_port"
	if d.quarantineVLAN > 0 {
		op = "quarantine_vlan"
	}

	req := SwitchRequest{
		ActionID:       action.ID,
		Operation:      op,
		TargetMAC:      dev.MAC,
		TargetIP:       dev.IP,
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
// Restoring is never refused — it can only give a device its access back —
// but it names the device the way Apply did, so the adapter finds the port
// it changed.
func (d *SwitchPortDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	req := SwitchRequest{
		ActionID:  action.ID,
		Operation: "restore",
		TargetMAC: action.TargetMAC,
		TargetIP:  action.TargetIP,
	}
	if key, err := parseDeviceMAC(action.TargetMAC); err == nil {
		req.TargetMAC = formatMACKey(key)
	}
	if addr, err := parseDeviceIP(action.TargetIP); err == nil {
		req.TargetIP = addr.String()
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
	if d.secret != "" {
		req.Header.Set(events.SignatureHeader, events.SignPayload(d.secret, body))
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", requestError(err, endpointOf(d.webhookURL)))
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// The adapter answered and said no: by its contract nothing changed.
	// A transport error above is different — the request may have been
	// carried out — and is returned as is.
	errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return NotApplied(fmt.Errorf("webhook %d: %s", resp.StatusCode, scrub(errBody, urlSecrets(d.webhookURL)...)))
}
