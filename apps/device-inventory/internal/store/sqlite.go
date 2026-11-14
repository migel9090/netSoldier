package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// Binding states, as reported in Device.IPState.
const (
	IPTentative = "tentative" // claimed once, not yet re-confirmed
	IPLive      = "live"      // re-confirmed, last confirmation within the TTL
	IPStale     = "stale"     // not confirmed within the TTL; may be taken over
)

// Device is one row of the inventory as the API shows it.
type Device struct {
	MAC            string    `json:"mac"`
	IP             string    `json:"ip"`
	IPSource       string    `json:"ip_source,omitempty"`
	IPState        string    `json:"ip_state,omitempty"`
	IPSince        time.Time `json:"ip_since,omitzero"`
	IPConfirmedAt  time.Time `json:"ip_confirmed_at,omitzero"`
	Hostname       string    `json:"hostname"`
	HostnameSource string    `json:"hostname_source,omitempty"`
	Fingerprint    string    `json:"dhcp_fingerprint"`
	VendorClass    string    `json:"vendor_class"`
	Vendor         string    `json:"vendor"`
	OS             string    `json:"os"`
	DeviceType     string    `json:"device_type"`
	RandomizedMAC  bool      `json:"randomized_mac"`
	// RotationOf names the row this device probably used before a MAC
	// rotation. It is a hint for the operator; nothing moves along it.
	RotationOf    string     `json:"rotation_of,omitempty"`
	Labels        []string   `json:"labels"`
	Established   bool       `json:"established"`
	ConflictCount int        `json:"conflict_count"`
	Conflicts     []Conflict `json:"conflicts,omitempty"`
	FirstSeen     time.Time  `json:"first_seen"`
	LastSeen      time.Time  `json:"last_seen"`

	confirmations int
}

// Conflict is a claim the store refused because it contradicted a live
// binding or an established device.
//
// Kinds:
//   - ip_taken: Claimant claimed IP, which MAC holds with a live binding.
//   - ip_moved: MAC claimed Value while holding IP with a live binding.
//   - name: an equal-strength source offered Value as MAC's name.
//   - profile: a DHCP profile (options 55/60) Value differing from MAC's.
type Conflict struct {
	Kind      string    `json:"kind"`
	MAC       string    `json:"mac"`
	Claimant  string    `json:"claimant,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Value     string    `json:"value,omitempty"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`

	// New is set when this sighting created the conflict record.
	New bool `json:"-"`
}

// Options tune the store. Zero values take the defaults below.
type Options struct {
	MaxDevices       int           // row cap; default 5000
	BindingTTL       time.Duration // binding lapses without confirmation; default 1h
	EstablishedAfter time.Duration // seen across this long = established; default 24h
	Coalesce         time.Duration // identical sightings within this are not rewritten; default 15s
	PerSourceRate    float64       // sustained sightings/s per MAC or address; default 2
	PerSourceBurst   int           // default 20
	NewDeviceRate    float64       // new rows/s across all sources; default 1
	NewDeviceBurst   int           // default 100
	MaxConflicts     int           // conflict records kept; default 10000
	ConflictWindow   time.Duration // conflicts this recent are shown on a device; default 24h
	Now              func() time.Time
}

func (o Options) withDefaults() Options {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if o.MaxDevices <= 0 {
		o.MaxDevices = 5000
	}
	def(&o.BindingTTL, time.Hour)
	def(&o.EstablishedAfter, 24*time.Hour)
	def(&o.Coalesce, 15*time.Second)
	def(&o.ConflictWindow, 24*time.Hour)
	if o.PerSourceRate <= 0 {
		o.PerSourceRate = 2
	}
	if o.PerSourceBurst <= 0 {
		o.PerSourceBurst = 20
	}
	if o.NewDeviceRate <= 0 {
		o.NewDeviceRate = 1
	}
	if o.NewDeviceBurst <= 0 {
		o.NewDeviceBurst = 100
	}
	if o.MaxConflicts <= 0 {
		o.MaxConflicts = 10000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// Store is the inventory.
type Store struct {
	db     *sql.DB
	opts   Options
	limits *limiter

	mu    sync.Mutex
	count int
}

// ErrNotFound is returned for a MAC the inventory does not know.
var ErrNotFound = errors.New("device not found")

// Open opens the inventory with default options.
func Open(path string) (*Store, error) { return OpenWithOptions(path, Options{}) }

// OpenWithOptions opens (creating or migrating) the inventory at path.
func OpenWithOptions(path string, opts Options) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS devices (
		mac          TEXT PRIMARY KEY,
		ip           TEXT NOT NULL DEFAULT '',
		hostname     TEXT NOT NULL DEFAULT '',
		fingerprint  TEXT NOT NULL DEFAULT '',
		vendor_class TEXT NOT NULL DEFAULT '',
		vendor       TEXT NOT NULL DEFAULT '',
		os           TEXT NOT NULL DEFAULT '',
		device_type  TEXT NOT NULL DEFAULT '',
		stable_id    TEXT NOT NULL DEFAULT '',
		labels       TEXT NOT NULL DEFAULT '[]',
		randomized_mac INTEGER NOT NULL DEFAULT 0,
		first_seen   TEXT NOT NULL,
		last_seen    TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	// Additive migrations for databases created by an earlier version.
	// Errors are expected when the column already exists; anything else is
	// logged so a genuine migration failure is not invisible.
	for _, col := range []string{"vendor", "os", "device_type", "stable_id"} {
		migrate(db, fmt.Sprintf(`ALTER TABLE devices ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, col))
	}
	migrate(db, `ALTER TABLE devices ADD COLUMN labels TEXT NOT NULL DEFAULT '[]'`)
	migrate(db, `ALTER TABLE devices ADD COLUMN randomized_mac INTEGER NOT NULL DEFAULT 0`)
	migrate(db, `CREATE INDEX IF NOT EXISTS idx_last_seen ON devices(last_seen)`)

	if err := migrateV2(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate to schema v2: %w", err)
	}

	s := &Store{db: db, opts: opts.withDefaults()}
	s.limits = newLimiter(s.opts)
	if err := db.QueryRow(`SELECT count(*) FROM devices`).Scan(&s.count); err != nil {
		db.Close()
		return nil, fmt.Errorf("count devices: %w", err)
	}
	return s, nil
}

// migrate runs an additive DDL statement, tolerating "already exists".
func migrate(db *sql.DB, stmt string) {
	if _, err := db.Exec(stmt); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "duplicate column") || strings.Contains(msg, "already exists") {
			return
		}
		slog.Warn("schema migration failed", "statement", stmt, "error", err)
	}
}

const schemaVersion = 2

// migrateV2 brings a v1 table (or a fresh one) to the identity model: value
// provenance, binding freshness, unique addresses, the conflicts table, and a
// clean-up of what the v1 code let in (non-MAC keys, raw bytes in names,
// several rows on one address).
func migrateV2(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= schemaVersion {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	existing := map[string]bool{}
	rows, err := tx.Query(`SELECT name FROM pragma_table_info('devices')`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		existing[name] = true
	}
	rows.Close()
	for _, col := range []string{
		"hostname_source TEXT NOT NULL DEFAULT ''",
		"ip_source TEXT NOT NULL DEFAULT ''",
		"ip_since TEXT NOT NULL DEFAULT ''",
		"ip_confirmed_at TEXT NOT NULL DEFAULT ''",
		"ip_confirmations INTEGER NOT NULL DEFAULT 0",
		"rotation_of TEXT NOT NULL DEFAULT ''",
	} {
		if name, _, _ := strings.Cut(col, " "); !existing[name] {
			if _, err := tx.Exec(`ALTER TABLE devices ADD COLUMN ` + col); err != nil {
				return err
			}
		}
	}

	type legacy struct{ mac, labels, hostname, vendorClass string }
	var all []legacy
	rows, err = tx.Query(`SELECT mac, labels, hostname, vendor_class FROM devices`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.mac, &l.labels, &l.hostname, &l.vendorClass); err != nil {
			rows.Close()
			return err
		}
		all = append(all, l)
	}
	rows.Close()
	for _, l := range all {
		if canon, ok := discovery.ParseMAC(l.mac); !ok || canon != l.mac {
			// v1 accepted any DHCP hlen, so some keys are not MACs.
			// Operator-labelled rows are kept as they are.
			if l.labels == "[]" || l.labels == "" {
				if _, err := tx.Exec(`DELETE FROM devices WHERE mac = ?`, l.mac); err != nil {
					return err
				}
			}
			continue
		}
		host := discovery.SanitizeText(l.hostname, discovery.MaxNameLen)
		vc := discovery.SanitizeText(l.vendorClass, discovery.MaxVendorClassLen)
		if host != l.hostname || vc != l.vendorClass {
			if _, err := tx.Exec(`UPDATE devices SET hostname = ?, vendor_class = ? WHERE mac = ?`, host, vc, l.mac); err != nil {
				return err
			}
		}
	}

	for _, stmt := range []string{
		// One holder per address: keep whoever was seen last.
		`UPDATE devices SET ip = '' WHERE ip != '' AND rowid NOT IN (
			SELECT rowid FROM (
				SELECT rowid, ROW_NUMBER() OVER (PARTITION BY ip ORDER BY last_seen DESC, mac) AS rn
				FROM devices WHERE ip != '')
			WHERE rn = 1)`,
		// v1 bindings have no history: they start out tentative.
		`UPDATE devices SET ip_since = last_seen, ip_confirmed_at = last_seen, ip_confirmations = 0
			WHERE ip != '' AND ip_since = ''`,
		`DROP INDEX IF EXISTS idx_ip`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_holder ON devices(ip) WHERE ip != ''`,
		// stable_id re-keyed rows on client-chosen DHCP options; it is gone.
		`DROP INDEX IF EXISTS idx_stable_id`,
		`UPDATE devices SET stable_id = '' WHERE stable_id != ''`,
		`CREATE TABLE IF NOT EXISTS conflicts (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			kind       TEXT NOT NULL,
			mac        TEXT NOT NULL,
			claimant   TEXT NOT NULL DEFAULT '',
			ip         TEXT NOT NULL DEFAULT '',
			value      TEXT NOT NULL DEFAULT '',
			source     TEXT NOT NULL,
			first_seen TEXT NOT NULL,
			last_seen  TEXT NOT NULL,
			count      INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_key ON conflicts(kind, mac, claimant, ip, value, source)`,
		`CREATE INDEX IF NOT EXISTS idx_conflicts_mac ON conflicts(mac, last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_conflicts_claimant ON conflicts(claimant, last_seen) WHERE claimant != ''`,
		fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion),
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", strings.Fields(stmt)[0], err)
		}
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// Count is the number of rows, kept in memory so callers on the sighting path
// never run a full count.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func (s *Store) addCount(delta int) {
	s.mu.Lock()
	s.count += delta
	s.mu.Unlock()
}

const deviceColumns = `mac, ip, ip_source, ip_since, ip_confirmed_at, ip_confirmations,
	hostname, hostname_source, fingerprint, vendor_class, vendor, os, device_type,
	randomized_mac, rotation_of, labels, first_seen, last_seen`

type scanner interface{ Scan(dest ...any) error }

func scanDevice(sc scanner, extra ...any) (*Device, error) {
	var d Device
	var since, confirmed, labels, first, last string
	var randomized int
	dest := []any{&d.MAC, &d.IP, &d.IPSource, &since, &confirmed, &d.confirmations,
		&d.Hostname, &d.HostnameSource, &d.Fingerprint, &d.VendorClass, &d.Vendor, &d.OS, &d.DeviceType,
		&randomized, &d.RotationOf, &labels, &first, &last}
	if err := sc.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	d.IPSince = parseTime(since)
	d.IPConfirmedAt = parseTime(confirmed)
	d.FirstSeen = parseTime(first)
	d.LastSeen = parseTime(last)
	d.RandomizedMAC = randomized != 0
	_ = json.Unmarshal([]byte(labels), &d.Labels)
	if d.Labels == nil {
		d.Labels = []string{}
	}
	return &d, nil
}

// derive fills the fields that depend on the clock and the options.
func (s *Store) derive(d *Device, now time.Time) {
	d.IPState = s.bindingState(d, now)
	d.Established = s.established(d)
}

func (s *Store) bindingState(d *Device, now time.Time) string {
	switch {
	case d.IP == "":
		return ""
	case now.Sub(d.IPConfirmedAt) >= s.opts.BindingTTL:
		return IPStale
	case d.confirmations == 0:
		return IPTentative
	}
	return IPLive
}

func (s *Store) established(d *Device) bool {
	return len(d.Labels) > 0 || d.LastSeen.Sub(d.FirstSeen) >= s.opts.EstablishedAfter
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
