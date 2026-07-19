// Package dhcpfp identifies device OS/type from passive DHCP metadata
// (option 55 parameter request list + option 60 vendor class) using a
// first-party lookup table.
//
// This is NOT Fingerbank: it bundles no Fingerbank data and calls no
// Fingerbank API. The Fingerbank device DB is proprietary (non-commercial
// redistribution), so it is deliberately not used — this table is our own,
// hand-curated from common DHCP fingerprints, and is fully open and
// monetization-safe. See COMPLIANCE.md.
package dhcpfp

import "strings"

// Profile describes a device based on its DHCP fingerprint.
type Profile struct {
	OS         string // "iOS", "macOS", "Windows", "Android", "Linux", "ChromeOS", etc.
	DeviceType string // "phone", "tablet", "laptop", "desktop", "tv", "iot", "router", "printer"
}

// Lookup identifies a device profile from its DHCP fingerprint (option 55
// parameter request list, comma-separated) and vendor class (option 60).
// Returns nil if the device cannot be identified.
func Lookup(fingerprint, vendorClass string) *Profile {
	if p := matchVendorClass(vendorClass); p != nil {
		return p
	}
	if p := matchFingerprint(fingerprint); p != nil {
		return p
	}
	return nil
}

func matchVendorClass(vc string) *Profile {
	if vc == "" {
		return nil
	}
	lower := strings.ToLower(vc)

	if strings.HasPrefix(lower, "android-dhcp-") {
		return &Profile{OS: "Android", DeviceType: "phone"}
	}
	if strings.Contains(lower, "msft 5.0") {
		return &Profile{OS: "Windows", DeviceType: "desktop"}
	}
	if strings.Contains(lower, "msft ") {
		return &Profile{OS: "Windows", DeviceType: "desktop"}
	}
	if strings.HasPrefix(lower, "dhcpcd") && strings.Contains(lower, "linux") {
		return &Profile{OS: "Linux", DeviceType: "desktop"}
	}
	if strings.HasPrefix(lower, "dhcpcd") {
		return &Profile{OS: "Linux", DeviceType: "desktop"}
	}
	if strings.HasPrefix(lower, "udhcp") {
		return &Profile{OS: "Linux", DeviceType: "iot"}
	}
	if strings.Contains(lower, "roku") {
		return &Profile{OS: "Roku OS", DeviceType: "tv"}
	}
	if strings.Contains(lower, "xbox") {
		return &Profile{OS: "Xbox", DeviceType: "console"}
	}
	if strings.Contains(lower, "playstation") || strings.HasPrefix(lower, "ps5") || strings.HasPrefix(lower, "ps4") {
		return &Profile{OS: "PlayStation", DeviceType: "console"}
	}
	if strings.Contains(lower, "printer") || strings.Contains(lower, "hp ") {
		return &Profile{OS: "Embedded", DeviceType: "printer"}
	}
	if strings.Contains(lower, "chromecast") || strings.Contains(lower, "chrome") {
		return &Profile{OS: "ChromeOS", DeviceType: "iot"}
	}
	return nil
}

func matchFingerprint(fp string) *Profile {
	if fp == "" {
		return nil
	}
	if p, ok := prlDB[fp]; ok {
		return &p
	}
	return nil
}

// prlDB maps DHCP option 55 parameter request lists to device profiles.
// Keys are comma-separated option codes in request order.
var prlDB = map[string]Profile{
	// ── Apple iOS / iPadOS ─────────────────────────────────────
	"1,121,3,6,15,119,252":                                       {OS: "iOS", DeviceType: "phone"},
	"1,121,3,6,15,119,252,95,44,46":                              {OS: "iOS", DeviceType: "phone"},
	"1,3,6,15,119,252":                                           {OS: "iOS", DeviceType: "phone"},
	"1,3,6,15,119,252,67,13":                                     {OS: "iOS", DeviceType: "phone"},
	"1,121,3,6,15,119,252,95,44,46,67":                           {OS: "iOS", DeviceType: "phone"},

	// ── Apple macOS ────────────────────────────────────────────
	"1,121,3,6,15,119,252,95,44,46,101":                          {OS: "macOS", DeviceType: "laptop"},
	"1,3,6,15,119,95,252,44,46":                                  {OS: "macOS", DeviceType: "laptop"},
	"1,3,6,15,119,95,252,44,46,47":                               {OS: "macOS", DeviceType: "laptop"},
	"1,121,3,6,15,119,252,95,44,46,47":                           {OS: "macOS", DeviceType: "laptop"},

	// ── Apple tvOS / HomePod ───────────────────────────────────
	"1,3,6,15,119,252,95":                                        {OS: "tvOS", DeviceType: "tv"},

	// ── Windows 10/11 ──────────────────────────────────────────
	"1,3,6,15,31,33,43,44,46,47,119,121,249,252":                 {OS: "Windows", DeviceType: "desktop"},
	"1,15,3,6,44,46,47,31,33,121,249,252,43":                     {OS: "Windows", DeviceType: "desktop"},
	"1,15,3,6,44,46,47,31,33,121,249,252":                        {OS: "Windows", DeviceType: "desktop"},
	"1,3,6,15,31,33,43,44,46,47,119,121,249,252,0":               {OS: "Windows", DeviceType: "desktop"},

	// ── Windows 7/8 ────────────────────────────────────────────
	"1,15,3,6,44,46,47,31,33,249,43":                             {OS: "Windows", DeviceType: "desktop"},
	"1,15,3,6,44,46,47,31,33,249,43,252":                         {OS: "Windows", DeviceType: "desktop"},

	// ── Android ────────────────────────────────────────────────
	"1,3,6,15,26,28,51,58,59,43":                                 {OS: "Android", DeviceType: "phone"},
	"1,33,3,6,15,26,28,51,58,59,43":                              {OS: "Android", DeviceType: "phone"},
	"1,3,6,15,26,28,51,58,59":                                    {OS: "Android", DeviceType: "phone"},
	"1,3,6,15,26,28,51,58,59,43,114":                             {OS: "Android", DeviceType: "phone"},

	// ── ChromeOS ───────────────────────────────────────────────
	"1,121,33,3,6,12,15,26,28,51,54,58,59,119,43":                {OS: "ChromeOS", DeviceType: "laptop"},

	// ── Linux (dhclient) ───────────────────────────────────────
	"1,28,2,3,15,6,119,12,44,47,26,121,42":                       {OS: "Linux", DeviceType: "desktop"},
	"1,28,2,121,15,6,12,40,41,42,26,119,3":                       {OS: "Linux", DeviceType: "desktop"},
	"1,28,2,3,15,6,12":                                           {OS: "Linux", DeviceType: "desktop"},

	// ── Linux (NetworkManager) ─────────────────────────────────
	"1,28,2,3,15,6,119,12,44,47,26,121":                          {OS: "Linux", DeviceType: "desktop"},

	// ── Linux (systemd-networkd) ───────────────────────────────
	"1,2,3,6,12,15,26,28,121,119":                                {OS: "Linux", DeviceType: "desktop"},

	// ── Smart TV / media ───────────────────────────────────────
	"1,3,6,12,15,28,42,125":                                      {OS: "Tizen", DeviceType: "tv"},
	"1,3,6,15,28,33":                                             {OS: "webOS", DeviceType: "tv"},
	"1,3,28,6":                                                   {OS: "Embedded", DeviceType: "tv"},

	// ── IoT / embedded ─────────────────────────────────────────
	"1,3,6,15,28":                                                {OS: "Embedded", DeviceType: "iot"},
	"1,3,6,12,15,28,42":                                          {OS: "Embedded", DeviceType: "iot"},
	"1,3,6,15":                                                   {OS: "Embedded", DeviceType: "iot"},
	"1,3,6":                                                      {OS: "Embedded", DeviceType: "iot"},
	"1,3,6,28":                                                   {OS: "Embedded", DeviceType: "iot"},

	// ── Printers ───────────────────────────────────────────────
	"1,3,6,15,44,47,12":                                          {OS: "Embedded", DeviceType: "printer"},
	"6,3,1,15,66,67,13,44,12":                                    {OS: "Embedded", DeviceType: "printer"},

	// ── Network equipment ──────────────────────────────────────
	"1,66,6,3,15,150":                                            {OS: "IOS", DeviceType: "router"},
	"1,3,6,15,150,43,125":                                        {OS: "IOS", DeviceType: "router"},
}
