package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Cursors records how far each input has been read, so a restart resumes
// where the previous process stopped instead of at "now". Each reader owns
// the encoding of its position; the store only keeps the bytes.
type Cursors struct {
	db  *sql.DB
	now func() time.Time
}

// Cursors returns the cursor table.
func (s *Store) Cursors() *Cursors {
	return &Cursors{db: s.db, now: time.Now}
}

// Load returns the stored position of source, and when it was written.
// ok is false when the source has never saved one.
func (c *Cursors) Load(source string) (position []byte, updated time.Time, ok bool, err error) {
	var ms int64
	err = c.db.QueryRow(`SELECT position, updated_at FROM ingest_cursors WHERE source = ?`, source).
		Scan(&position, &ms)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, time.Time{}, false, nil
	case err != nil:
		storeErrors.WithLabelValues("cursor_read").Inc()
		return nil, time.Time{}, false, fmt.Errorf("read cursor %s: %w", source, err)
	}
	return position, fromMilli(ms), true, nil
}

// Save replaces the stored position of source.
func (c *Cursors) Save(source string, position []byte) error {
	if _, err := c.db.Exec(`INSERT INTO ingest_cursors (source, position, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (source) DO UPDATE SET position = excluded.position, updated_at = excluded.updated_at`,
		source, position, unixMilli(c.now())); err != nil {
		storeErrors.WithLabelValues("cursor_write").Inc()
		return fmt.Errorf("save cursor %s: %w", source, err)
	}
	return nil
}
