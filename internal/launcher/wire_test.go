package launcher

import (
	"strings"
	"testing"
)

// Validate bounds the Windows fields: a pipe only under the session prefix
// with 32 hex digits, a password of at most 256 bytes, neither on a probe.
func TestValidatePipeAndPassword(t *testing.T) {
	base := Request{V: Version, Kind: KindTerminal, Device: "d", Login: "alice", Cols: 80, Rows: 24, Term: "xterm"}
	pipe := SessionPipePrefix + strings.Repeat("ab", 16)
	for _, tc := range []struct {
		name string
		edit func(*Request)
		ok   bool
	}{
		{"no pipe", func(*Request) {}, true},
		{"session pipe", func(r *Request) { r.Pipe = pipe }, true},
		{"password", func(r *Request) { r.Pipe, r.Password = pipe, []byte(strings.Repeat("p", maxPassword)) }, true},
		{"other pipe", func(r *Request) { r.Pipe = `\\.\pipe\localport-session` }, false},
		{"upper-case hex", func(r *Request) { r.Pipe = SessionPipePrefix + strings.Repeat("AB", 16) }, false},
		{"remote pipe", func(r *Request) { r.Pipe = `\\host\pipe\localport-session-` + strings.Repeat("ab", 16) }, false},
		{"long password", func(r *Request) { r.Password = []byte(strings.Repeat("p", maxPassword+1)) }, false},
		{"probe with pipe", func(r *Request) { *r = Request{V: Version, Kind: KindProbe, Pipe: pipe} }, false},
		{"probe with password", func(r *Request) { *r = Request{V: Version, Kind: KindProbe, Password: []byte("x")} }, false},
	} {
		r := base
		tc.edit(&r)
		if err := r.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Validate = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}
