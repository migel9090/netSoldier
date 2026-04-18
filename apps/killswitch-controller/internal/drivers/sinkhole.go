package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// SinkholeDriver blocks malicious domains via AdGuard Home's custom
// filtering rules API. This is the safest enforcement mechanism:
// fastest to apply/revert, only affects DNS resolution, no network
// topology changes.
type SinkholeDriver struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
}

func NewSinkholeDriver(adguardURL, user, password string) *SinkholeDriver {
	return &SinkholeDriver{
		baseURL:  strings.TrimRight(adguardURL, "/"),
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (d *SinkholeDriver) Name() string { return "dns_sinkhole" }

// Apply adds a blocking rule for the action's domain to AdGuard Home.
func (d *SinkholeDriver) Apply(ctx context.Context, action *events.EnforcementAction) error {
	if action.BlockedDomain == "" {
		return fmt.Errorf("no domain to block")
	}
	rule := "||" + action.BlockedDomain + "^"

	rules, err := d.getRules(ctx)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	for _, r := range rules {
		if r == rule {
			slog.Debug("sinkhole rule already exists", "domain", action.BlockedDomain)
			return nil
		}
	}

	rules = append(rules, rule)
	if err := d.setRules(ctx, rules); err != nil {
		return fmt.Errorf("set rules: %w", err)
	}

	slog.Info("sinkhole applied", "domain", action.BlockedDomain, "action_id", action.ID)
	return nil
}

// Revert removes the blocking rule for the action's domain from AdGuard Home.
func (d *SinkholeDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	if action.BlockedDomain == "" {
		return nil
	}
	rule := "||" + action.BlockedDomain + "^"

	rules, err := d.getRules(ctx)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	filtered := make([]string, 0, len(rules))
	for _, r := range rules {
		if r != rule {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == len(rules) {
		slog.Debug("sinkhole rule not found, nothing to revert", "domain", action.BlockedDomain)
		return nil
	}

	if err := d.setRules(ctx, filtered); err != nil {
		return fmt.Errorf("set rules: %w", err)
	}

	slog.Info("sinkhole reverted", "domain", action.BlockedDomain, "action_id", action.ID)
	return nil
}

func (d *SinkholeDriver) getRules(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/control/filtering/status", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(d.user, d.password)

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("adguard %d: %s", resp.StatusCode, body)
	}

	var status struct {
		UserRules []string `json:"user_rules"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return status.UserRules, nil
}

func (d *SinkholeDriver) setRules(ctx context.Context, rules []string) error {
	body, _ := json.Marshal(map[string]any{"rules": rules})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+"/control/filtering/set_rules", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(d.user, d.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("adguard %d: %s", resp.StatusCode, errBody)
	}
	return nil
}
