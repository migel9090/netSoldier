package indicator

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text makes a free-text field (threat name, analyst comment, reference,
// source, tag) safe to carry into any export format: invalid UTF-8 is
// replaced, tabs and line breaks become single spaces, every other control
// or format character (C0/C1 controls, line and paragraph separators,
// bidirectional overrides, zero-width characters) is removed, runs of
// spaces are collapsed, and the result is trimmed and cut to at most max
// bytes on a rune boundary.
//
// A tab and a newline in a feed's "threat" field were enough to inject an
// arbitrary well-formed line — "0.0.0.0/0 Intel::SUBNET" — into the Zeek
// Intel file. Ingest strips them here; each exporter still escapes for its
// own format as a second line of defence.
func Text(s string, max int) string {
	if s == "" {
		return ""
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	b.Grow(min(len(s), max+utf8.UTFMax))
	space := false
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f' ||
			r == '\u0085' || r == '\u2028' || r == '\u2029' || unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		}
		sep := 0
		if space && b.Len() > 0 {
			sep = 1
		}
		space = false
		if b.Len()+sep+utf8.RuneLen(r) > max {
			break
		}
		if sep == 1 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Tags sanitises a tag list with Text, drops empty and duplicate tags and
// keeps at most MaxTags.
func Tags(tags []string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(tags), MaxTags))
	seen := make(map[string]struct{}, len(tags))
	for _, t := range tags {
		t = Text(t, MaxTagLen)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
		if len(out) == MaxTags {
			break
		}
	}
	return out
}

// hasControlOrSpace reports whether s contains whitespace, a control
// character or a format character anywhere. Indicator values are refused
// outright rather than cleaned: a value with a tab in it is not a typo
// worth repairing.
func hasControlOrSpace(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}
