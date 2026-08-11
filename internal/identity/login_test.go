package identity

import "testing"

func TestHostnameDropsTheMDNSSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"jump-box.local": "jump-box",
		"jump-box":       "jump-box",
		".local":         ".local", // trimming would leave nothing to show
		"":               "",
	} {
		if got := trimHostname(in); got != want {
			t.Errorf("trimHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
