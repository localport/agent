// Package ports parses and checks a device's port ceiling (--allow-ports).
package ports

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// MaxRanges bounds a ceiling. The edge refuses a registration with more.
const MaxRanges = 64

// Range is an inclusive range of ports, From ≤ To.
type Range struct {
	From uint16
	To   uint16
}

// Ceiling is a sorted, non-overlapping set of ranges. Nil means no ceiling.
type Ceiling []Range

// Allows reports whether port is inside the ceiling. A nil ceiling allows all.
func (c Ceiling) Allows(port uint16) bool {
	if c == nil {
		return true
	}
	for _, r := range c {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

// String renders the ceiling in the flag's grammar: "80,502,8000-8100".
func (c Ceiling) String() string {
	parts := make([]string, len(c))
	for i, r := range c {
		if r.From == r.To {
			parts[i] = strconv.Itoa(int(r.From))
		} else {
			parts[i] = fmt.Sprintf("%d-%d", r.From, r.To)
		}
	}
	return strings.Join(parts, ",")
}

// ParseFlag reads a comma-separated list, the --allow-ports value. An empty
// value is no ceiling.
func ParseFlag(value string) (Ceiling, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return Parse(strings.Split(value, ","))
}

// Parse reads entries of the form "502" or "8000-8100" and returns them sorted,
// with overlapping and adjacent ranges merged. No entries is no ceiling.
func Parse(entries []string) (Ceiling, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > MaxRanges {
		return nil, fmt.Errorf("at most %d port entries are allowed, got %d", MaxRanges, len(entries))
	}
	ranges := make([]Range, 0, len(entries))
	for _, entry := range entries {
		r, err := parseRange(strings.TrimSpace(entry))
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, r)
	}
	slices.SortFunc(ranges, func(a, b Range) int { return int(a.From) - int(b.From) })
	merged := Ceiling{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if uint32(r.From) <= uint32(last.To)+1 {
			last.To = max(last.To, r.To)
			continue
		}
		merged = append(merged, r)
	}
	return merged, nil
}

func parseRange(entry string) (Range, error) {
	low, high, isRange := strings.Cut(entry, "-")
	from, err := parsePort(low)
	if err != nil {
		return Range{}, fmt.Errorf("port %q: %w", entry, err)
	}
	if !isRange {
		return Range{From: from, To: from}, nil
	}
	to, err := parsePort(high)
	if err != nil {
		return Range{}, fmt.Errorf("port range %q: %w", entry, err)
	}
	if from > to {
		return Range{}, fmt.Errorf("port range %q: start is above end", entry)
	}
	return Range{From: from, To: to}, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("expected a port from 1 to 65535")
	}
	return uint16(n), nil
}
