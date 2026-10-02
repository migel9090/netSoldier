package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// domainPattern is what we are willing to turn into an AdGuard filter rule.
//
// A rule is built as "||" + domain + "^" and AdGuard stores user_rules as
// newline-separated text, so an unvalidated domain containing a newline
// injects ADDITIONAL filter rules — a value ending in "^\n||*^" would append
// a catch-all block and take DNS down for the whole household. The domain
// originates in a detection event, so it is attacker-influenceable; it has to
// be validated here, at the point where it becomes a control-plane
// instruction.
var domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// validateDomain normalizes and checks a domain destined for a filter rule.
func validateDomain(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain too long (%d bytes)", len(d))
	}
	if !domainPattern.MatchString(d) {
		return "", fmt.Errorf("refusing to build a filter rule from %q: not a plain hostname", domain)
	}
	return d, nil
}

// SinkholeDriver blocks malicious domains via AdGuard Home's custom
// filtering rules API. This is the safest enforcement mechanism:
// fastest to apply/revert, only affects DNS resolution, no network
// topology changes.
type SinkholeDriver struct {
	baseURL  string
	user     string
	password string
	http     *http.Client

	// rulesMu serializes the read-modify-write cycle against AdGuard.
	// Apply/Revert fetch the full user_rules list, change one entry and
	// write the whole list back; the driver is called concurrently from
	// /evaluate, /approve, /revert and the TTL goroutine, so without this
	// two overlapping calls would lose one another's edit — dropping a
	// block, or resurrecting one that had just been reverted.
	rulesMu sync.Mutex
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
	domain, err := validateDomain(action.BlockedDomain)
	if err != nil {
		return err
	}
	rule := "||" + domain + "^"

	d.rulesMu.Lock()
	defer d.rulesMu.Unlock()

	rules, err := d.getRules(ctx)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	for _, r := range rules {
		if r == rule {
			slog.Debug("sinkhole rule already exists", "domain", domain)
			return nil
		}
	}

	rules = append(rules, rule)
	if err := d.setRules(ctx, rules); err != nil {
		return fmt.Errorf("set rules: %w", err)
	}

	slog.Info("sinkhole applied", "domain", domain, "action_id", action.ID)
	return nil
}

// Revert removes the blocking rule for the action's domain from AdGuard Home.
func (d *SinkholeDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	domain, err := validateDomain(action.BlockedDomain)
	if err != nil {
		// Nothing valid was ever written, so there is nothing to remove.
		slog.Debug("sinkhole revert: no valid domain recorded", "action_id", action.ID)
		return nil
	}
	rule := "||" + domain + "^"

	d.rulesMu.Lock()
	defer d.rulesMu.Unlock()

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
		slog.Debug("sinkhole rule not found, nothing to revert", "domain", domain)
		return nil
	}

	if err := d.setRules(ctx, filtered); err != nil {
		return fmt.Errorf("set rules: %w", err)
	}

	slog.Info("sinkhole reverted", "domain", domain, "action_id", action.ID)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return status.UserRules, nil
}

func (d *SinkholeDriver) setRules(ctx context.Context, rules []string) error {
	body, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+"/control/filtering/set_rules", bytes.NewReader(body))
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
