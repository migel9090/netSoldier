package store

import (
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// Outcome is what the store did with a sighting.
type Outcome string

const (
	Applied     Outcome = "applied"      // written (possibly as conflicts only)
	Coalesced   Outcome = "coalesced"    // identical to one written moments ago; nothing to do
	RateLimited Outcome = "rate_limited" // the source, or new-device admission, is over its rate
	Full        Outcome = "full"         // new device refused: at the cap and nothing evictable
	Invalid     Outcome = "invalid"      // nothing usable after normalisation
	Unbound     Outcome = "unbound"      // a name for an address nobody currently holds
)

// Result reports what a sighting changed.
type Result struct {
	Outcome Outcome
	Created bool
	// Changed is set when an identity field (address, name, profile) changed,
	// i.e. when the device is worth a new snapshot downstream.
	Changed bool
	// Device is the device after the sighting (Applied only).
	Device *Device
	// Released is the previous holder of an address that was taken over.
	Released  *Device
	Rebind    *Rebind
	Conflicts []Conflict
	Evicted   string
	Linked    string
}

// Rebind describes an address that changed hands, or a device that changed
// address, because the previous binding had lapsed.
type Rebind struct {
	IP              string
	ToMAC           string
	FromMAC         string // previous holder of IP, if any
	FromEstablished bool
	PreviousIP      string // ToMAC's previous address, if any
}

var fingerprintRe = regexp.MustCompile(`^[0-9]{1,3}(,[0-9]{1,3}){0,254}$`)

// normalize re-applies the bounds a listener should already have applied, so
// the store's invariants do not depend on every producer getting them right.
func normalize(o discovery.Sighting) (discovery.Sighting, bool) {
	if o.Source.Rank() == 0 {
		return o, false
	}
	o.Name = discovery.SanitizeText(o.Name, discovery.MaxNameLen)
	o.VendorClass = discovery.SanitizeText(o.VendorClass, discovery.MaxVendorClassLen)
	o.Vendor = discovery.SanitizeText(o.Vendor, discovery.MaxNameLen)
	o.OS = discovery.SanitizeText(o.OS, 32)
	o.DeviceType = discovery.SanitizeText(o.DeviceType, 32)
	if !fingerprintRe.MatchString(o.Fingerprint) {
		o.Fingerprint = ""
	}
	if o.MAC != "" {
		mac, ok := discovery.ParseMAC(o.MAC)
		if !ok {
			return o, false
		}
		o.MAC = mac
	}
	if o.IP != "" {
		ip, ok := discovery.ParseUsableIPv4(o.IP)
		if !ok && o.MAC == "" {
			return o, false
		}
		o.IP = ip
	}
	if o.MAC == "" && (o.IP == "" || o.Name == "") {
		return o, false
	}
	return o, true
}

func signature(o discovery.Sighting) string {
	return string(o.Source) + "\x00" + o.IP + "\x00" + o.Name + "\x00" + o.Fingerprint + "\x00" + o.VendorClass
}

// Observe applies one sighting under the identity model (see the package
// documentation) and reports what changed.
func (s *Store) Observe(o discovery.Sighting) (Result, error) {
	o, ok := normalize(o)
	if !ok {
		return Result{Outcome: Invalid}, nil
	}
	wall := s.opts.Now()
	now := wall.UTC().Truncate(time.Second)

	key := o.MAC
	if key == "" {
		key = "ip:" + o.IP
	}
	sig := signature(o)
	if out, ok := s.limits.admit(key, sig, wall); !ok {
		return Result{Outcome: out}, nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()

	var res Result
	if o.MAC == "" {
		err = s.observeByIP(tx, o, now, wall, &res)
	} else {
		err = s.observeMAC(tx, o, now, wall, &res)
	}
	if err != nil {
		return Result{}, err
	}
	if res.Outcome != Applied {
		return res, nil
	}
	if err := tx.Commit(); err != nil {
		return Result{}, err
	}
	s.limits.remember(key, sig, wall)
	if res.Created {
		s.addCount(1)
	}
	if res.Evicted != "" {
		s.addCount(-1)
	}
	return res, nil
}

func (s *Store) observeMAC(tx *sql.Tx, o discovery.Sighting, now, wall time.Time, res *Result) error {
	d, err := getDevice(tx, `mac = ?`, o.MAC)
	if err != nil {
		return err
	}
	if d == nil {
		if !s.limits.allowNew(wall) {
			res.Outcome = RateLimited
			return nil
		}
		if s.Count() >= s.opts.MaxDevices {
			evicted, err := s.evictOne(tx, now)
			if err != nil {
				return err
			}
			if evicted == "" {
				res.Outcome = Full
				return nil
			}
			res.Evicted = evicted
		}
		d = &Device{
			MAC:           o.MAC,
			Vendor:        o.Vendor,
			RandomizedMAC: discovery.IsRandomizedMAC(o.MAC),
			Labels:        []string{},
			FirstSeen:     now,
			LastSeen:      now,
		}
		randomized := 0
		if d.RandomizedMAC {
			randomized = 1
		}
		if _, err := tx.Exec(`INSERT INTO devices (mac, vendor, randomized_mac, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?)`, d.MAC, d.Vendor, randomized, formatTime(now), formatTime(now)); err != nil {
			return err
		}
		res.Created, res.Changed = true, true
	} else {
		d.LastSeen = now
		if _, err := tx.Exec(`UPDATE devices SET last_seen = ?, vendor = CASE WHEN vendor = '' THEN ? ELSE vendor END
			WHERE mac = ?`, formatTime(now), o.Vendor, d.MAC); err != nil {
			return err
		}
	}

	established := s.established(d)
	if err := s.applyProfile(tx, d, o, established, now, res); err != nil {
		return err
	}
	named, err := s.applyName(tx, d, o, established, now, res, d.MAC, "")
	if err != nil {
		return err
	}
	if named && o.Source == discovery.SourceDHCP {
		if err := s.linkRotation(tx, d, res); err != nil {
			return err
		}
	}
	if err := s.applyBinding(tx, d, o, now, res); err != nil {
		return err
	}

	res.Outcome = Applied
	return s.finish(tx, d.MAC, now, res)
}

// observeByIP handles a name offered for an address (mDNS, SSDP). It never
// creates a row, a binding or a last_seen bump: the datagram proves nothing
// about which MAC sent it.
func (s *Store) observeByIP(tx *sql.Tx, o discovery.Sighting, now, _ time.Time, res *Result) error {
	d, err := getDevice(tx, byIP, o.IP)
	if err != nil {
		return err
	}
	if d == nil || s.bindingState(d, now) == IPStale {
		res.Outcome = Unbound
		return nil
	}
	if _, err := s.applyName(tx, d, o, s.established(d), now, res, "", o.IP); err != nil {
		return err
	}
	res.Outcome = Applied
	return s.finish(tx, d.MAC, now, res)
}

func (s *Store) finish(tx *sql.Tx, mac string, now time.Time, res *Result) error {
	d, err := getDevice(tx, `mac = ?`, mac)
	if err != nil {
		return err
	}
	s.derive(d, now)
	res.Device = d
	if res.Released != nil {
		s.derive(res.Released, now)
	}
	return nil
}

// applyName sets the device's name when the source outranks the one that set
// the current name, or equals it while the device is not established. An
// equal source contradicting an established device is a conflict; a weaker
// source is not evidence against a stronger one and is ignored.
func (s *Store) applyName(tx *sql.Tx, d *Device, o discovery.Sighting, established bool,
	now time.Time, res *Result, claimant, ip string) (bool, error) {
	if o.Name == "" {
		return false, nil
	}
	newRank := o.Source.Rank()
	curRank := discovery.Source(d.HostnameSource).Rank()
	switch {
	case o.Name == d.Hostname:
		if newRank > curRank {
			d.HostnameSource = string(o.Source)
			_, err := tx.Exec(`UPDATE devices SET hostname_source = ? WHERE mac = ?`, d.HostnameSource, d.MAC)
			return false, err
		}
		return false, nil
	case newRank > curRank, newRank == curRank && !established:
		d.Hostname, d.HostnameSource = o.Name, string(o.Source)
		if _, err := tx.Exec(`UPDATE devices SET hostname = ?, hostname_source = ? WHERE mac = ?`,
			d.Hostname, d.HostnameSource, d.MAC); err != nil {
			return false, err
		}
		res.Changed = true
		return true, nil
	case newRank == curRank:
		return false, s.recordConflict(tx, Conflict{Kind: "name", MAC: d.MAC, Claimant: claimant, IP: ip,
			Value: o.Name, Source: string(o.Source)}, now, res)
	}
	return false, nil
}

// applyProfile records the DHCP profile (options 55 and 60, and what dhcpfp
// derived from them). An established device keeps the profile it has; a
// different one under its MAC is what a cloned MAC looks like, so it is a
// conflict.
func (s *Store) applyProfile(tx *sql.Tx, d *Device, o discovery.Sighting, established bool,
	now time.Time, res *Result) error {
	if o.Fingerprint == "" && o.VendorClass == "" {
		return nil
	}
	differs := (o.Fingerprint != "" && o.Fingerprint != d.Fingerprint) ||
		(o.VendorClass != "" && o.VendorClass != d.VendorClass)
	if !differs {
		return nil
	}
	if established && (d.Fingerprint != "" || d.VendorClass != "") {
		return s.recordConflict(tx, Conflict{Kind: "profile", MAC: d.MAC, Claimant: d.MAC,
			Value: "55=" + o.Fingerprint + " 60=" + o.VendorClass, Source: string(o.Source)}, now, res)
	}
	if o.Fingerprint != "" {
		d.Fingerprint = o.Fingerprint
	}
	if o.VendorClass != "" {
		d.VendorClass = o.VendorClass
	}
	if o.OS != "" || o.DeviceType != "" {
		d.OS, d.DeviceType = o.OS, o.DeviceType
	}
	if _, err := tx.Exec(`UPDATE devices SET fingerprint = ?, vendor_class = ?, os = ?, device_type = ? WHERE mac = ?`,
		d.Fingerprint, d.VendorClass, d.OS, d.DeviceType, d.MAC); err != nil {
		return err
	}
	res.Changed = true
	return nil
}

// applyBinding handles a claim that d uses o.IP. See the package
// documentation for the rules; in short, a live binding is never displaced by
// a passive claim, a lapsed or tentative one is.
func (s *Store) applyBinding(tx *sql.Tx, d *Device, o discovery.Sighting, now time.Time, res *Result) error {
	if o.IP == "" {
		return nil
	}
	if d.IP == o.IP {
		src := d.IPSource
		if o.Source.Rank() > discovery.Source(src).Rank() {
			src = string(o.Source)
		}
		_, err := tx.Exec(`UPDATE devices SET ip_confirmed_at = ?, ip_confirmations = ip_confirmations + 1,
			ip_source = ? WHERE mac = ?`, formatTime(now), src, d.MAC)
		return err
	}

	holder, err := getDevice(tx, byIP, o.IP)
	if err != nil {
		return err
	}
	authoritative := o.Source.Authoritative()
	if holder != nil && !authoritative && s.bindingState(holder, now) == IPLive {
		return s.recordConflict(tx, Conflict{Kind: "ip_taken", MAC: holder.MAC, Claimant: d.MAC,
			IP: o.IP, Source: string(o.Source)}, now, res)
	}
	if d.IP != "" && !authoritative && s.bindingState(d, now) == IPLive {
		return s.recordConflict(tx, Conflict{Kind: "ip_moved", MAC: d.MAC, Claimant: d.MAC,
			IP: d.IP, Value: o.IP, Source: string(o.Source)}, now, res)
	}

	rb := &Rebind{IP: o.IP, ToMAC: d.MAC, PreviousIP: d.IP}
	if holder != nil {
		if _, err := tx.Exec(`UPDATE devices SET ip = '', ip_source = '', ip_since = '', ip_confirmed_at = '',
			ip_confirmations = 0 WHERE mac = ?`, holder.MAC); err != nil {
			return err
		}
		rb.FromMAC, rb.FromEstablished = holder.MAC, s.established(holder)
		if res.Released, err = getDevice(tx, `mac = ?`, holder.MAC); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE devices SET ip = ?, ip_source = ?, ip_since = ?, ip_confirmed_at = ?,
		ip_confirmations = 0 WHERE mac = ?`, o.IP, string(o.Source), formatTime(now), formatTime(now), d.MAC); err != nil {
		return err
	}
	if rb.FromMAC != "" || rb.PreviousIP != "" {
		res.Rebind = rb
	}
	d.IP = o.IP
	res.Changed = true
	return nil
}

// linkRotation records that a privacy-MAC device which just named itself over
// DHCP is probably the same physical device as exactly one earlier
// privacy-MAC row with the same DHCP name and vendor class that went quiet
// before this one appeared. It is a hint only: no label, binding or history
// moves. No hostname means no link (two phones with the vendor default and no
// name are two phones).
func (s *Store) linkRotation(tx *sql.Tx, d *Device, res *Result) error {
	if !d.RandomizedMAC || d.RotationOf != "" || d.VendorClass == "" || d.Hostname == "" {
		return nil
	}
	rows, err := tx.Query(`SELECT mac FROM devices WHERE mac != ? AND randomized_mac = 1
		AND hostname = ? AND hostname_source = ? AND vendor_class = ? AND last_seen <= ? LIMIT 2`,
		d.MAC, d.Hostname, string(discovery.SourceDHCP), d.VendorClass, formatTime(d.FirstSeen))
	if err != nil {
		return err
	}
	var candidates []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, mac)
	}
	rows.Close()
	if len(candidates) != 1 {
		return rows.Err()
	}
	if _, err := tx.Exec(`UPDATE devices SET rotation_of = ? WHERE mac = ?`, candidates[0], d.MAC); err != nil {
		return err
	}
	d.RotationOf, res.Linked = candidates[0], candidates[0]
	return nil
}

// evictOne deletes the least valuable row to make room: never a labelled
// one; non-established before established; without a live binding before
// with one; oldest sighting first. It returns "" when only labelled rows are
// left.
func (s *Store) evictOne(tx *sql.Tx, now time.Time) (string, error) {
	var mac string
	err := tx.QueryRow(`SELECT mac FROM devices WHERE labels IN ('[]', '')
		ORDER BY (CAST(strftime('%s', last_seen) AS INTEGER) - CAST(strftime('%s', first_seen) AS INTEGER) >= ?) ASC,
			(ip != '' AND ip_confirmations > 0 AND ip_confirmed_at >= ?) ASC,
			last_seen ASC, mac ASC
		LIMIT 1`, int64(s.opts.EstablishedAfter/time.Second), formatTime(now.Add(-s.opts.BindingTTL))).Scan(&mac)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(`DELETE FROM devices WHERE mac = ?`, mac)
	return mac, err
}

// recordConflict stores (or bumps) a conflict record and appends it to res.
// The table is capped by id: every so often the records older than the
// newest MaxConflicts are dropped, which needs no count.
func (s *Store) recordConflict(tx *sql.Tx, c Conflict, now time.Time, res *Result) error {
	ts := formatTime(now)
	r, err := tx.Exec(`UPDATE conflicts SET last_seen = ?, count = count + 1
		WHERE kind = ? AND mac = ? AND claimant = ? AND ip = ? AND value = ? AND source = ?`,
		ts, c.Kind, c.MAC, c.Claimant, c.IP, c.Value, c.Source)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		r, err = tx.Exec(`INSERT INTO conflicts (kind, mac, claimant, ip, value, source, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, c.Kind, c.MAC, c.Claimant, c.IP, c.Value, c.Source, ts, ts)
		if err != nil {
			return err
		}
		c.New = true
		if id, err := r.LastInsertId(); err == nil && id%64 == 0 {
			if _, err := tx.Exec(`DELETE FROM conflicts WHERE id <= ?`, id-int64(s.opts.MaxConflicts)); err != nil {
				return err
			}
		}
	}
	if err := tx.QueryRow(`SELECT first_seen, last_seen, count FROM conflicts
		WHERE kind = ? AND mac = ? AND claimant = ? AND ip = ? AND value = ? AND source = ?`,
		c.Kind, c.MAC, c.Claimant, c.IP, c.Value, c.Source).Scan(&ts, new(string), &c.Count); err != nil {
		return err
	}
	c.FirstSeen, c.LastSeen = parseTime(ts), now
	res.Conflicts = append(res.Conflicts, c)
	return nil
}

func getDevice(q interface {
	QueryRow(string, ...any) *sql.Row
}, where string, arg any) (*Device, error) {
	d, err := scanDevice(q.QueryRow(`SELECT `+deviceColumns+` FROM devices WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

// byIP selects the holder of an address. The redundant `ip != ”` is what
// lets SQLite use the partial unique index idx_ip_holder instead of scanning
// the table on every sighting.
const byIP = `ip = ? AND ip != ''`
