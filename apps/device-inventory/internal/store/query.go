package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// Label limits, enforced here and by the API.
const (
	MaxLabels   = 32
	MaxLabelLen = 64
)

// maxConflictsShown bounds the conflicts attached to one device.
const maxConflictsShown = 10

// ErrInvalidLabels is returned for a label set outside the limits.
var ErrInvalidLabels = errors.New("invalid labels")

// NormalizeLabels trims and de-duplicates labels and enforces the limits: at
// most MaxLabels, each 1..MaxLabelLen bytes of printable text.
func NormalizeLabels(labels []string) ([]string, error) {
	if len(labels) > MaxLabels {
		return nil, fmt.Errorf("%w: at most %d labels", ErrInvalidLabels, MaxLabels)
	}
	out := make([]string, 0, len(labels))
	seen := make(map[string]bool, len(labels))
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l == "" || len(l) > MaxLabelLen || discovery.SanitizeText(l, MaxLabelLen) != l {
			return nil, fmt.Errorf("%w: each label must be 1-%d bytes of printable text", ErrInvalidLabels, MaxLabelLen)
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out, nil
}

// trustOrder lists labelled devices first, then established ones, then
// devices with a live binding, then the rest, most recently seen first
// within each group: a flood of fresh rows (one sighting each, so tentative
// at best) cannot push a known or active device off the first page.
const trustOrder = `ORDER BY (d.labels NOT IN ('[]', '')) DESC,
	(CAST(strftime('%s', d.last_seen) AS INTEGER) - CAST(strftime('%s', d.first_seen) AS INTEGER) >= ?) DESC,
	(d.ip != '' AND d.ip_confirmations > 0 AND d.ip_confirmed_at >= ?) DESC,
	d.last_seen DESC, d.mac ASC`

// conflictCount is the number of recent conflicts a device (d) is involved
// in. GET /devices and GET /devices/{mac} both report it, so a device has one
// conflict count whichever endpoint is asked; only the attached list is
// capped.
const conflictCount = `(SELECT count(*) FROM conflicts c
	WHERE (c.mac = d.mac OR (c.claimant = d.mac AND c.claimant != '')) AND c.last_seen >= ?)`

// List returns one page of devices in trust order (see trustOrder), each
// with the number of recent conflicts it is involved in.
func (s *Store) List(limit, offset int) ([]Device, error) {
	now := s.opts.Now().UTC()
	rows, err := s.db.Query(`SELECT `+prefixed(deviceColumns)+`, `+conflictCount+`
		FROM devices d `+trustOrder+` LIMIT ? OFFSET ?`,
		formatTime(now.Add(-s.opts.ConflictWindow)), int64(s.opts.EstablishedAfter/time.Second),
		formatTime(now.Add(-s.opts.BindingTTL)), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]Device, 0)
	for rows.Next() {
		var n int
		d, err := scanDevice(rows, &n)
		if err != nil {
			return nil, err
		}
		d.ConflictCount = n
		s.derive(d, now)
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// ListBound returns every device that holds an address (bounded by the row
// cap), for the topology view.
func (s *Store) ListBound() ([]Device, error) {
	now := s.opts.Now().UTC()
	rows, err := s.db.Query(`SELECT ` + deviceColumns + ` FROM devices WHERE ip != '' ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]Device, 0)
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		s.derive(d, now)
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

// GetDevice returns a device by canonical MAC with its recent conflicts, or
// nil if it is unknown.
func (s *Store) GetDevice(mac string) (*Device, error) {
	return s.getWithConflicts(`mac = ?`, mac, false)
}

// GetByIP returns the device currently holding ip: a binding confirmed
// within the TTL, tentative or live. A lapsed binding is not "current" and
// gives nil.
func (s *Store) GetByIP(ip string) (*Device, error) {
	return s.getWithConflicts(byIP, ip, true)
}

func (s *Store) getWithConflicts(where string, arg any, currentOnly bool) (*Device, error) {
	now := s.opts.Now().UTC()
	d, err := getDevice(s.db, where, arg)
	if err != nil || d == nil {
		return nil, err
	}
	s.derive(d, now)
	if currentOnly && d.IPState == IPStale {
		return nil, nil
	}
	if d.Conflicts, err = s.conflictsFor(d.MAC, now); err != nil {
		return nil, err
	}
	// The real total, not len(d.Conflicts): that list stops at
	// maxConflictsShown, and a device under a flood of claims would
	// otherwise show 10 here and the true number in the list view.
	if err := s.db.QueryRow(`SELECT `+conflictCount+` FROM devices d WHERE d.mac = ?`,
		formatTime(now.Add(-s.opts.ConflictWindow)), d.MAC).Scan(&d.ConflictCount); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) conflictsFor(mac string, now time.Time) ([]Conflict, error) {
	rows, err := s.db.Query(`SELECT kind, mac, claimant, ip, value, source, first_seen, last_seen, count
		FROM conflicts WHERE (mac = ? OR (claimant = ? AND claimant != '')) AND last_seen >= ?
		ORDER BY last_seen DESC, id DESC LIMIT ?`,
		mac, mac, formatTime(now.Add(-s.opts.ConflictWindow)), maxConflictsShown)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Conflict
	for rows.Next() {
		var c Conflict
		var first, last string
		if err := rows.Scan(&c.Kind, &c.MAC, &c.Claimant, &c.IP, &c.Value, &c.Source, &first, &last, &c.Count); err != nil {
			return nil, err
		}
		c.FirstSeen, c.LastSeen = parseTime(first), parseTime(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetLabels replaces the label set of a known device and returns it.
func (s *Store) SetLabels(mac string, labels []string) (*Device, error) {
	labels, err := NormalizeLabels(labels)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(labels)
	if err != nil {
		return nil, fmt.Errorf("marshal labels: %w", err)
	}
	res, err := s.db.Exec(`UPDATE devices SET labels = ? WHERE mac = ?`, string(b), mac)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.GetDevice(mac)
}

// Prune deletes devices not seen within maxAge, keeping any that carry
// operator labels, and conflict records older than maxAge. Returns the number
// of devices removed.
func (s *Store) Prune(maxAge time.Duration) (int64, error) {
	cutoff := formatTime(s.opts.Now().UTC().Add(-maxAge))
	res, err := s.db.Exec(`DELETE FROM devices WHERE last_seen < ? AND labels IN ('[]', '')`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.Exec(`DELETE FROM conflicts WHERE last_seen < ?`, cutoff); err != nil {
		return n, err
	}
	if n > 0 {
		s.addCount(-int(n))
		slog.Info("pruned stale devices", "removed", n, "older_than", maxAge)
	}
	return n, nil
}

func prefixed(cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = "d." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}
