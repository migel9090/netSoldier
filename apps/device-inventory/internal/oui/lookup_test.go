package oui

import "testing"

func TestLookup(t *testing.T) {
	for mac, want := range map[string]string{
		"b8:27:eb:00:00:01": "Raspberry Pi",
		"B8-27-EB-00-00-01": "Raspberry Pi",
		"00:11:24:aa:bb:01": "Apple",
		"02:00:00:00:00:01": "",
		"b8:27":             "",
		"":                  "",
	} {
		if got := Lookup(mac); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestTableKeysAreCanonical(t *testing.T) {
	for k := range db {
		if len(k) != 8 || k[2] != ':' || k[5] != ':' {
			t.Errorf("key %q is not AA:BB:CC", k)
		}
	}
}

func FuzzLookup(f *testing.F) {
	f.Add("aa:bb:cc:dd:ee:ff")
	f.Add("\xff\xfe:")
	f.Fuzz(func(t *testing.T, s string) { _ = Lookup(s) })
}
