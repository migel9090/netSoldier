package ioc

import (
	"strings"
	"time"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// Normalized IoC type constants. They are the shared library's names, so
// the JSON export and the detection-engine's matcher cannot disagree.
const (
	TypeDomain     = indicator.TypeDomain
	TypeIP         = indicator.TypeIP
	TypeURL        = indicator.TypeURL
	TypeMD5        = indicator.TypeMD5
	TypeSHA256     = indicator.TypeSHA256
	TypeJA3        = indicator.TypeJA3
	TypeTLSFP      = indicator.TypeTLSFP // TLS client fingerprint (JA4-format)
	TypeCertSHA1   = indicator.TypeCertSHA1
	TypeCertSHA256 = indicator.TypeCertSHA256
)

// Indicator is the common representation of an indicator of compromise
// across all threat intelligence sources.
type Indicator struct {
	Type       string
	Value      string
	Source     string
	Threat     string
	Confidence int
	// FirstSeen and LastSeen are the feed's own claims about the indicator
	// and are carried through as metadata only; they say nothing about
	// whether the feed still lists it.
	FirstSeen time.Time
	LastSeen  time.Time
	Tags      []string
	Reference string
	// LastAsserted is stamped by the store on every upsert: the last time a
	// feed answered with this indicator in it. Expiry is measured from here.
	LastAsserted time.Time `json:",omitzero"`
}

// Key returns the deduplication key for this indicator.
func (i Indicator) Key() string {
	return i.Type + ":" + strings.ToLower(i.Value)
}

// Merge updates this indicator with metadata from another indicator
// sharing the same key. Keeps the richer / more recent data.
func (i *Indicator) Merge(other Indicator) {
	if other.Confidence > i.Confidence {
		i.Confidence = other.Confidence
	}
	if !other.FirstSeen.IsZero() && (i.FirstSeen.IsZero() || other.FirstSeen.Before(i.FirstSeen)) {
		i.FirstSeen = other.FirstSeen
	}
	if other.LastSeen.After(i.LastSeen) {
		i.LastSeen = other.LastSeen
	}
	if i.Threat == "" && other.Threat != "" {
		i.Threat = other.Threat
	}
	if i.Reference == "" && other.Reference != "" {
		i.Reference = other.Reference
	}
	if !strings.Contains(i.Source, other.Source) {
		i.Source = i.Source + "," + other.Source
	}
	i.Tags = mergeTags(i.Tags, other.Tags)
}

func mergeTags(a, b []string) []string {
	seen := make(map[string]struct{}, len(a))
	for _, t := range a {
		seen[t] = struct{}{}
	}
	merged := append([]string{}, a...)
	for _, t := range b {
		if _, ok := seen[t]; !ok {
			merged = append(merged, t)
		}
	}
	return merged
}
