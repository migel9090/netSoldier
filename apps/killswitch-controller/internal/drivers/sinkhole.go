package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"golang.org/x/net/publicsuffix"
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
//
// Being a syntactically valid hostname is not enough. "203.0.113.9" matches
// the hostname grammar, and AdGuard would store ||203.0.113.9^ as a rule that
// does not block the address. A public suffix is worse: ||co.uk^ or
// ||github.io^ blocks every registrant under it, which for a household is
// most of a country's web or every GitHub Pages site. Both are refused here,
// at the point a value becomes a control-plane instruction, whatever
// upstream said.
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
	// netip refuses leading zeros ("192.168.001.001"), so an all-numeric
	// last label catches the spellings it does not parse: no real TLD is
	// numeric.
	if _, err := netip.ParseAddr(d); err == nil || isNumeric(d[strings.LastIndexByte(d, '.')+1:]) {
		return "", fmt.Errorf("refusing to build a filter rule from %q: it is an IP address, not a domain", domain)
	}
	if suffix, _ := publicsuffix.PublicSuffix(d); suffix == d {
		return "", fmt.Errorf("refusing to build a filter rule from %q: it is a public suffix, "+
			"blocking it would block every domain registered under it", domain)
	}
	return d, nil
}

func isNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// SinkholeDriver blocks malicious domains via AdGuard Home's custom
// filtering rules API. This is the safest enforcement mechanism:
// fastest to apply/revert, only affects DNS resolution, no network
// topology changes.
//
// AdGuard's rules are shared: the operator's own, and one per domain this
// service blocks — which several actions can need at once (the same C2
// domain seen from two devices). The driver therefore owns exactly what it
// added, through the ledger:
//
//   - every action that needs a rule holds a reference to it, and the rule
//     is removed only when the last reference goes;
//   - a rule that was already present when first needed is the operator's,
//     is recorded as not owned and is never removed;
//   - the claim is written to the ledger before AdGuard is, so a crash
//     between the two leaves a claim reconciliation can resolve, never an
//     unowned rule;
//   - a status reply it cannot read as a rule list stops it before it
//     writes: the write replaces the whole list, so writing from a
//     misread list would erase every operator rule.
type SinkholeDriver struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
	ledger   RuleLedger

	// rulesMu serializes the read-modify-write cycle against AdGuard and
	// the ledger. Apply/Revert fetch the full user_rules list, change one
	// entry and write the whole list back; without this two overlapping
	// calls would lose one another's edit.
	rulesMu sync.Mutex
}

// NewSinkholeDriver returns a driver for the AdGuard Home at adguardURL.
// ledger records rule ownership; nil keeps it in memory only, which forgets
// ownership on restart and is meant for tests.
func NewSinkholeDriver(adguardURL, user, password string, ledger RuleLedger) *SinkholeDriver {
	if ledger == nil {
		ledger = newMemoryLedger()
	}
	return &SinkholeDriver{
		baseURL:  strings.TrimRight(adguardURL, "/"),
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
		ledger:   ledger,
	}
}

func (d *SinkholeDriver) Name() string { return events.ActionDNSSinkhole }

func ruleFor(domain string) string { return "||" + domain + "^" }

// Apply makes sure a blocking rule for the action's domain is in AdGuard
// and that the action holds a reference to it.
func (d *SinkholeDriver) Apply(ctx context.Context, action *events.EnforcementAction) error {
	domain, err := validateDomain(action.BlockedDomain)
	if err != nil {
		return NotApplied(err)
	}
	rule := ruleFor(domain)

	d.rulesMu.Lock()
	defer d.rulesMu.Unlock()

	held, holds, err := d.ledger.SinkholeRef(action.ID)
	if err != nil {
		return NotApplied(fmt.Errorf("read rule ledger: %w", err))
	}
	if holds && held != rule {
		return NotApplied(fmt.Errorf("action already holds rule %s", held))
	}
	rules, err := d.getRules(ctx)
	if err != nil {
		return NotApplied(fmt.Errorf("read current rules: %w", err))
	}
	present := contains(rules, rule)
	if !holds || !present {
		// Claim first: if the process dies after AdGuard accepted the rule,
		// the ledger already says it is ours.
		if err := d.ledger.ClaimSinkholeRule(action.ID, rule, !present); err != nil {
			return NotApplied(fmt.Errorf("record rule ownership: %w", err))
		}
	}
	if present {
		slog.Info("sinkhole rule already present; referenced", "domain", domain, "action_id", action.ID)
		return nil
	}
	if err := d.setRules(ctx, append(rules, rule)); err != nil {
		// AdGuard may or may not have stored it; the claim stands until a
		// Revert resolves it.
		return fmt.Errorf("set rules: %w", err)
	}
	slog.Info("sinkhole applied", "domain", domain, "action_id", action.ID)
	return nil
}

// Revert drops the action's reference, and removes the rule from AdGuard
// only when the action held the last reference to a rule this service
// added. An action that holds nothing has nothing to revert.
func (d *SinkholeDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	d.rulesMu.Lock()
	defer d.rulesMu.Unlock()

	rule, holds, err := d.ledger.SinkholeRef(action.ID)
	if err != nil {
		return fmt.Errorf("read rule ledger: %w", err)
	}
	if !holds {
		return nil
	}
	info, refs, _, err := d.ledger.SinkholeRule(rule)
	if err != nil {
		return fmt.Errorf("read rule ledger: %w", err)
	}
	if refs > 1 || !info.Owned {
		if err := d.ledger.ReleaseSinkholeRef(action.ID, !info.Owned); err != nil {
			return fmt.Errorf("release rule reference: %w", err)
		}
		slog.Info("sinkhole reference released; rule kept", "rule", rule, "action_id", action.ID,
			"other_references", refs-1, "owned", info.Owned)
		return nil
	}
	rules, err := d.getRules(ctx)
	if err != nil {
		return fmt.Errorf("read current rules: %w", err)
	}
	if contains(rules, rule) {
		filtered := make([]string, 0, len(rules))
		for _, r := range rules {
			if r != rule {
				filtered = append(filtered, r)
			}
		}
		if err := d.setRules(ctx, filtered); err != nil {
			return fmt.Errorf("set rules: %w", err)
		}
	}
	if err := d.ledger.ReleaseSinkholeRef(action.ID, true); err != nil {
		return fmt.Errorf("release rule reference: %w", err)
	}
	slog.Info("sinkhole reverted", "rule", rule, "action_id", action.ID)
	return nil
}

// SinkholeClaim is an action the controller considers enforced by the
// sinkhole, as reconciliation sees it.
type SinkholeClaim struct {
	ActionID string
	Domain   string
}

// SinkholeReport is what reconciliation found.
type SinkholeReport struct {
	// Missing: enforced actions whose rule is no longer in AdGuard. Their
	// references have been dropped; the caller records them as ended.
	Missing []string
	// Removed: rules this service added that nothing needs any more,
	// removed from AdGuard.
	Removed []string
	// StaleRefs: references held by actions that are not enforced.
	StaleRefs []string
	// Adopted: enforced actions that held no reference while their rule was
	// present; now referenced, as not owned, so it is never removed by us.
	Adopted []string
}

// Reconcile compares the ledger with AdGuard and repairs the difference in
// the safe direction: what nobody needs and this service added is removed,
// what is missing is reported (never silently re-created), and a rule this
// service did not add is never touched. enforced lists the actions the
// controller considers in force; inFlight says which actions have a driver
// call under way and must be left alone. It fails closed: when AdGuard's
// rules cannot be read, nothing is written.
func (d *SinkholeDriver) Reconcile(ctx context.Context, enforced []SinkholeClaim,
	inFlight func(actionID string) bool) (SinkholeReport, error) {
	var rep SinkholeReport
	d.rulesMu.Lock()
	defer d.rulesMu.Unlock()

	rules, err := d.getRules(ctx)
	if err != nil {
		return rep, fmt.Errorf("read current rules: %w", err)
	}
	present := map[string]bool{}
	for _, r := range rules {
		present[r] = true
	}
	refs, err := d.ledger.SinkholeRefs()
	if err != nil {
		return rep, err
	}
	known, err := d.ledger.SinkholeRules()
	if err != nil {
		return rep, err
	}
	wanted := map[string]string{} // action -> rule
	for _, c := range enforced {
		if domain, err := validateDomain(c.Domain); err == nil {
			wanted[c.ActionID] = ruleFor(domain)
		}
	}

	keep := map[string]int{} // rule -> references that stay
	var drop []string        // actions whose reference goes
	held := map[string]bool{}
	for _, ref := range refs {
		held[ref.ActionID] = true
		switch _, isWanted := wanted[ref.ActionID]; {
		case inFlight(ref.ActionID):
			keep[ref.Rule]++
		case isWanted && present[ref.Rule]:
			keep[ref.Rule]++
		case isWanted:
			rep.Missing = append(rep.Missing, ref.ActionID)
			drop = append(drop, ref.ActionID)
		default:
			rep.StaleRefs = append(rep.StaleRefs, ref.ActionID)
			drop = append(drop, ref.ActionID)
		}
	}
	for _, c := range enforced {
		rule, ok := wanted[c.ActionID]
		if held[c.ActionID] || inFlight(c.ActionID) || !ok {
			continue
		}
		if present[rule] {
			rep.Adopted = append(rep.Adopted, c.ActionID)
			keep[rule]++
		} else {
			rep.Missing = append(rep.Missing, c.ActionID)
		}
	}

	var forget []string
	remove := map[string]bool{}
	for _, r := range known {
		if keep[r.Rule] > 0 {
			continue
		}
		forget = append(forget, r.Rule)
		if r.Owned && present[r.Rule] {
			remove[r.Rule] = true
			rep.Removed = append(rep.Removed, r.Rule)
		}
	}
	if len(remove) > 0 {
		filtered := make([]string, 0, len(rules))
		for _, r := range rules {
			if !remove[r] {
				filtered = append(filtered, r)
			}
		}
		if err := d.setRules(ctx, filtered); err != nil {
			return SinkholeReport{}, fmt.Errorf("remove orphaned rules: %w", err)
		}
	}
	var errs []error
	for _, id := range drop {
		errs = append(errs, d.ledger.ReleaseSinkholeRef(id, false))
	}
	for _, id := range rep.Adopted {
		errs = append(errs, d.ledger.ClaimSinkholeRule(id, wanted[id], false))
	}
	for _, rule := range forget {
		errs = append(errs, d.ledger.ForgetSinkholeRule(rule))
	}
	return rep, errors.Join(errs...)
}

func contains(rules []string, rule string) bool {
	for _, r := range rules {
		if r == rule {
			return true
		}
	}
	return false
}

// getRules reads AdGuard's user rules.
//
// A reply without a user_rules key is an error, not an empty list: the
// caller writes the list back whole, so reading a renamed or truncated
// field as "no rules" would wipe the operator's rules. A null value is an
// empty list — it is how AdGuard encodes a rule list that was never set.
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
		return nil, fmt.Errorf("adguard %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}

	var status map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode filtering status: %w", err)
	}
	raw, ok := status["user_rules"]
	if !ok {
		return nil, errors.New("filtering status has no user_rules: refusing to write a rule list " +
			"that would replace rules it could not read")
	}
	var rules []string
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("filtering status user_rules is not a list of strings: %w", err)
	}
	return rules, nil
}

func (d *SinkholeDriver) setRules(ctx context.Context, rules []string) error {
	if rules == nil {
		rules = []string{}
	}
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
		return fmt.Errorf("adguard %d: %s", resp.StatusCode, bytes.TrimSpace(errBody))
	}
	return nil
}
