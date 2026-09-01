package identity

import "testing"

// macOS reports its mDNS name, so a machine called `some-mac` answers
// `some-mac.local`. The suffix is an artefact of resolution, not the name.
func TestHostnameDropsTheMDNSSuffix(t *testing.T) {
	cases := map[string]string{
		"vkas-mac.local": "vkas-mac",
		"jump-box":       "jump-box",
		// Only the suffix goes, so a host genuinely called `local` keeps its name,
		// and one called `local.local` loses one level rather than both.
		"local":       "local",
		"local.local": "local",
		"":            "",
	}
	for in, want := range cases {
		if got := trimHostname(in); got != want {
			t.Errorf("trimHostname(%q) = %q, want %q", in, got, want)
		}
	}
}
