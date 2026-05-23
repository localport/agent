package cli

import "testing"

func TestExtractPositional(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		proto    string
		local    string
		restSize int
	}{
		{"tcp port", []string{"tcp", "18789", "-t", "tok"}, "tcp", "18789", 2},
		{"http host:port", []string{"http", "localhost:3000", "-t", "tok"}, "http", "localhost:3000", 2},
		{"tls port + flags", []string{"tls", "8443", "--token", "tok"}, "tls", "8443", 2},
		{"no positional, only flags", []string{"-t", "tok", "-l", "tcp://localhost:1"}, "", "", 4},
		{"unknown first arg", []string{"foo", "bar"}, "", "", 2},
		{"flag in arg[0]", []string{"-token", "tok", "-local", "tcp://x:1"}, "", "", 4},
		{"single positional", []string{"tcp"}, "", "", 1},
		{"proto followed by flag", []string{"tcp", "-t", "tok"}, "", "", 3},
		{"empty args", []string{}, "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proto, local, rest := extractPositional(tc.args)
			if proto != tc.proto {
				t.Errorf("proto = %q, want %q", proto, tc.proto)
			}
			if local != tc.local {
				t.Errorf("local = %q, want %q", local, tc.local)
			}
			if len(rest) != tc.restSize {
				t.Errorf("rest len = %d, want %d", len(rest), tc.restSize)
			}
		})
	}
}
