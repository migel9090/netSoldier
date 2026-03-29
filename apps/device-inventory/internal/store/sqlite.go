package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Device struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	Fingerprint string    `json:"dhcp_fingerprint"`
	VendorClass string    `json:"vendor_class"`
	Vendor      string    `json:"vendor"`
	OS          string    `json:"os"`
	DeviceType  string    `json:"device_type"`
	StableID    string    `json:"stable_id,omitempty"`
	Labels      []string  `json:"labels"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
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
		first_seen   TEXT NOT NULL,
		last_seen    TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	for _, col := range []string{"vendor", "os", "device_type", "stable_id"} {
		db.Exec(fmt.Sprintf(`ALTER TABLE devices ADD COLUMN %s TEXT NOT NULL DEFAULT ''`, col))
	}
	db.Exec(`ALTER TABLE devices ADD COLUMN labels TEXT NOT NULL DEFAULT '[]'`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_stable_id ON devices(stable_id) WHERE stable_id != ''`)

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Upsert(mac, ip, hostname, fingerprint, vendorClass, vendor string) error {
	return s.UpsertFull(mac, ip, hostname, fingerprint, vendorClass, vendor, "", "")
}

// UpsertFull inserts or updates a device with OS/device_type profiling.
// For MAC-randomized devices it correlates by vendorClass+hostname to
// track the same physical device across MAC rotations.
func (s *Store) UpsertFull(mac, ip, hostname, fingerprint, vendorClass, vendor, os, deviceType string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	if IsRandomizedMAC(mac) && (vendorClass != "" || hostname != "") {
		sid := StableID(vendorClass, hostname)
		res, err := s.db.Exec(`
			UPDATE devices SET
				mac          = ?,
				ip           = CASE WHEN ? != '' THEN ? ELSE ip END,
				hostname     = CASE WHEN ? != '' THEN ? ELSE hostname END,
				fingerprint  = CASE WHEN ? != '' THEN ? ELSE fingerprint END,
				vendor_class = CASE WHEN ? != '' THEN ? ELSE vendor_class END,
				vendor       = CASE WHEN ? != '' THEN ? ELSE vendor END,
				os           = CASE WHEN ? != '' THEN ? ELSE os END,
				device_type  = CASE WHEN ? != '' THEN ? ELSE device_type END,
				last_seen    = ?
			WHERE stable_id = ?`,
			mac,
			ip, ip, hostname, hostname,
			fingerprint, fingerprint, vendorClass, vendorClass,
			vendor, vendor, os, os, deviceType, deviceType,
			now, sid)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
		return s.insertDevice(mac, ip, hostname, fingerprint, vendorClass, vendor, os, deviceType, sid, now)
	}

	return s.insertDevice(mac, ip, hostname, fingerprint, vendorClass, vendor, os, deviceType, "", now)
}

func (s *Store) insertDevice(mac, ip, hostname, fingerprint, vendorClass, vendor, os, deviceType, stableID, now string) error {
	_, err := s.db.Exec(`
		INSERT INTO devices (mac, ip, hostname, fingerprint, vendor_class, vendor, os, device_type, stable_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip           = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE devices.ip END,
			hostname     = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
			fingerprint  = CASE WHEN excluded.fingerprint != '' THEN excluded.fingerprint ELSE devices.fingerprint END,
			vendor_class = CASE WHEN excluded.vendor_class != '' THEN excluded.vendor_class ELSE devices.vendor_class END,
			vendor       = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
			os           = CASE WHEN excluded.os != '' THEN excluded.os ELSE devices.os END,
			device_type  = CASE WHEN excluded.device_type != '' THEN excluded.device_type ELSE devices.device_type END,
			stable_id    = CASE WHEN excluded.stable_id != '' THEN excluded.stable_id ELSE devices.stable_id END,
			last_seen    = excluded.last_seen`,
		mac, ip, hostname, fingerprint, vendorClass, vendor, os, deviceType, stableID, now, now)
	return err
}

// SetLabels replaces the label set for a device identified by MAC.
func (s *Store) SetLabels(mac string, labels []string) error {
	b, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("marshal labels: %w", err)
	}
	res, err := s.db.Exec(`UPDATE devices SET labels = ? WHERE mac = ?`, string(b), mac)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("device %s not found", mac)
	}
	return nil
}

// GetDevice returns a single device by MAC, or nil if not found.
func (s *Store) GetDevice(mac string) (*Device, error) {
	var d Device
	var first, last, labelsJSON string
	err := s.db.QueryRow(`
		SELECT mac, ip, hostname, fingerprint, vendor_class, vendor, os, device_type, stable_id, labels, first_seen, last_seen
		FROM devices WHERE mac = ?`, mac).Scan(
		&d.MAC, &d.IP, &d.Hostname, &d.Fingerprint, &d.VendorClass, &d.Vendor,
		&d.OS, &d.DeviceType, &d.StableID, &labelsJSON, &first, &last)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(labelsJSON), &d.Labels)
	if d.Labels == nil {
		d.Labels = []string{}
	}
	d.FirstSeen, _ = time.Parse(time.RFC3339, first)
	d.LastSeen, _ = time.Parse(time.RFC3339, last)
	return &d, nil
}

// IsRandomizedMAC returns true if the MAC has the locally-administered bit set,
// indicating a privacy-randomized address (iOS 14+, Android 10+, Windows 10+).
func IsRandomizedMAC(mac string) bool {
	mac = strings.ReplaceAll(mac, "-", ":")
	parts := strings.SplitN(mac, ":", 2)
	if len(parts) == 0 {
		return false
	}
	b, err := strconv.ParseUint(parts[0], 16, 8)
	if err != nil {
		return false
	}
	return b&0x02 != 0
}

// StableID computes a deterministic identifier from DHCP attributes that
// remain constant across MAC randomization rotations.
func StableID(vendorClass, hostname string) string {
	h := sha256.Sum256([]byte(vendorClass + "|" + hostname))
	return fmt.Sprintf("%x", h[:6])
}

// EnrichByIP updates hostname for an existing device found by IP address.
// Only sets hostname if the new value is non-empty; always bumps last_seen.
func (s *Store) EnrichByIP(ip, hostname string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		UPDATE devices SET
			hostname  = CASE WHEN ? != '' THEN ? ELSE hostname END,
			last_seen = ?
		WHERE ip = ?`,
		hostname, hostname, now, ip)
	return err
}

func (s *Store) List() ([]Device, error) {
	rows, err := s.db.Query(`
		SELECT mac, ip, hostname, fingerprint, vendor_class, vendor, os, device_type, stable_id, labels, first_seen, last_seen
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]Device, 0)
	for rows.Next() {
		var d Device
		var first, last, labelsJSON string
		if err := rows.Scan(&d.MAC, &d.IP, &d.Hostname, &d.Fingerprint, &d.VendorClass, &d.Vendor,
			&d.OS, &d.DeviceType, &d.StableID, &labelsJSON, &first, &last); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(labelsJSON), &d.Labels)
		if d.Labels == nil {
			d.Labels = []string{}
		}
		d.FirstSeen, _ = time.Parse(time.RFC3339, first)
		d.LastSeen, _ = time.Parse(time.RFC3339, last)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}
