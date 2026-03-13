package misp

import (
	"strconv"
	"time"
)

// MISP attribute type constants used by the netSoldier detection pipeline.
const (
	TypeDomain  = "domain"
	TypeIPDst   = "ip-dst"
	TypeIPSrc   = "ip-src"
	TypeJA3     = "ja3-fingerprint-md5"
	TypeMD5     = "md5"
	TypeSHA256  = "sha256"
	TypeURL     = "url"
	TypeHostname = "hostname"
)

// Attribute represents a single MISP indicator of compromise.
type Attribute struct {
	ID        string `json:"id"`
	EventID   string `json:"event_id"`
	Type      string `json:"type"`
	Category  string `json:"category"`
	Value     string `json:"value"`
	Timestamp string `json:"timestamp"`
	Comment   string `json:"comment"`
	ToIDs     bool   `json:"to_ids"`
	UUID      string `json:"uuid"`
	Tags      []Tag  `json:"Tag"`
}

// Time parses the Unix timestamp string into a time.Time.
func (a Attribute) Time() time.Time {
	ts, err := strconv.ParseInt(a.Timestamp, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// HasTag returns true if the attribute carries a tag with the given name.
func (a Attribute) HasTag(name string) bool {
	for _, t := range a.Tags {
		if t.Name == name {
			return true
		}
	}
	return false
}

// Tag is a label attached to a MISP attribute or event.
type Tag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SearchRequest configures which attributes to fetch from MISP.
type SearchRequest struct {
	Types              []string // e.g. TypeDomain, TypeIPDst
	Published          bool     // only from published events
	Timestamp          string   // relative ("7d", "30d") or absolute unix timestamp
	Limit              int      // max results per page (0 = MISP default)
	Page               int      // 1-based page number (0 = first page)
	ToIDs              bool     // only attributes flagged for IDS export
	EnforceWarninglist bool     // exclude warninglist-matched values
}

type searchBody map[string]any

type attributeResponse struct {
	Response struct {
		Attribute []Attribute `json:"Attribute"`
	} `json:"response"`
}
