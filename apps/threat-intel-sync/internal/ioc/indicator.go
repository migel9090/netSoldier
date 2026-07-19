package ioc

import (
	"strings"
	"time"
)

// Normalized IoC type constants.
const (
	TypeDomain     = "domain"
	TypeIP         = "ip"
	TypeURL        = "url"
	TypeMD5        = "md5"
	TypeSHA256     = "sha256"
	TypeJA3        = "ja3"
	TypeJA4        = "ja4"
	TypeCertSHA1   = "cert-sha1"
	TypeCertSHA256 = "cert-sha256"
)

// Indicator is the common representation of an indicator of compromise
// across all threat intelligence sources.
type Indicator struct {
	Type       string
	Value      string
	Source     string
	Threat     string
	Confidence int
	FirstSeen  time.Time
	LastSeen   time.Time
	Tags       []string
	Reference  string
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
