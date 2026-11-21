package session

import (
	"testing"
	"time"
)

// The agent checks only the idle option's form; the range is the signer's policy.
func TestParseIdleChecksTheFormOnly(t *testing.T) {
	for v, want := range map[string]time.Duration{"1": time.Second, "299": 299 * time.Second, "14401": 14401 * time.Second} {
		if got, ok := parseIdle(v); !ok || got != want {
			t.Errorf("parseIdle(%q) = %v, %v; want %v", v, got, ok, want)
		}
	}
	for _, v := range []string{"", "0", "-5", "1.5", "01800", "30m", "+60", "36028797018965768"} {
		if _, ok := parseIdle(v); ok {
			t.Errorf("parseIdle(%q) accepted", v)
		}
	}
}
