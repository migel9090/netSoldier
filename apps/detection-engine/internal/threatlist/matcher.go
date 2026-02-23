package threatlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type Matcher struct {
	domains map[string]struct{}
}

func LoadFromFile(path string) (*Matcher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	domains := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains[strings.ToLower(line)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return &Matcher{domains: domains}, nil
}

func (m *Matcher) Size() int {
	return len(m.domains)
}

// Match checks the domain and all parent domains against the threat list.
// Returns the matched IoC entry and true if found.
func (m *Matcher) Match(domain string) (string, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		if _, ok := m.domains[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}
