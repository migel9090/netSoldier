package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Device struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	Hostname    string    `json:"hostname"`
	Fingerprint string    `json:"dhcp_fingerprint"`
	VendorClass string    `json:"vendor_class"`
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
		first_seen   TEXT NOT NULL,
		last_seen    TEXT NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Upsert(mac, ip, hostname, fingerprint, vendorClass string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO devices (mac, ip, hostname, fingerprint, vendor_class, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip           = CASE WHEN excluded.ip != '' THEN excluded.ip ELSE devices.ip END,
			hostname     = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
			fingerprint  = CASE WHEN excluded.fingerprint != '' THEN excluded.fingerprint ELSE devices.fingerprint END,
			vendor_class = CASE WHEN excluded.vendor_class != '' THEN excluded.vendor_class ELSE devices.vendor_class END,
			last_seen    = excluded.last_seen`,
		mac, ip, hostname, fingerprint, vendorClass, now, now)
	return err
}

func (s *Store) List() ([]Device, error) {
	rows, err := s.db.Query(`
		SELECT mac, ip, hostname, fingerprint, vendor_class, first_seen, last_seen
		FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	devices := make([]Device, 0)
	for rows.Next() {
		var d Device
		var first, last string
		if err := rows.Scan(&d.MAC, &d.IP, &d.Hostname, &d.Fingerprint, &d.VendorClass, &first, &last); err != nil {
			return nil, err
		}
		d.FirstSeen, _ = time.Parse(time.RFC3339, first)
		d.LastSeen, _ = time.Parse(time.RFC3339, last)
		devices = append(devices, d)
	}
	return devices, rows.Err()
}
