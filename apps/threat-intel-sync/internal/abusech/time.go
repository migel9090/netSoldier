package abusech

import (
	"strings"
	"time"
)

const abusechTimeLayout = "2006-01-02 15:04:05"

// parseAbusechTime handles the "2026-01-15 10:30:00 UTC" and
// "2026-01-15 10:30:00" formats used by abuse.ch APIs.
// Also accepts date-only "2026-01-15".
func parseAbusechTime(s string) time.Time {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " UTC")

	if t, err := time.Parse(abusechTimeLayout, s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}
