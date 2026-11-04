package launcher

import (
	"bytes"
	"encoding/base64"
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
		{"password", func(r *Request) {
			r.Pipe, r.HasPassword, r.Password = pipe, true, []byte(strings.Repeat("p", MaxPassword))
		}, true},
		{"password without its flag", func(r *Request) { r.Password = []byte("p") }, false},
		{"flag without a password", func(r *Request) { r.HasPassword = true }, false},
		{"other pipe", func(r *Request) { r.Pipe = `\\.\pipe\localport-session` }, false},
		{"upper-case hex", func(r *Request) { r.Pipe = SessionPipePrefix + strings.Repeat("AB", 16) }, false},
		{"remote pipe", func(r *Request) { r.Pipe = `\\host\pipe\localport-session-` + strings.Repeat("ab", 16) }, false},
		{"long password", func(r *Request) { r.HasPassword, r.Password = true, []byte(strings.Repeat("p", MaxPassword+1)) }, false},
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

// The password travels as a raw trailer: the JSON message never carries it,
// and the reader gets it back intact.
func TestHelperRequestPasswordTrailer(t *testing.T) {
	var buf bytes.Buffer
	secret := []byte("s3cret-pass")
	if err := WriteHelperRequest(&buf, HelperRequest{Kind: KindTerminal, Login: "alice", Password: secret}); err != nil {
		t.Fatal(err)
	}
	body, err := readBody(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, secret) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatalf("the JSON message carries the password: %s", body)
	}
	got, err := ReadHelperRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasPassword || string(got.Password) != string(secret) {
		t.Fatalf("read %+v", got)
	}
	var none bytes.Buffer
	if err := WriteHelperRequest(&none, HelperRequest{Kind: KindTerminal, Login: "alice"}); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHelperRequest(&none); err != nil || got.HasPassword || got.Password != nil || none.Len() != 0 {
		t.Fatalf("without a password: %+v, %v, %d bytes left", got, err, none.Len())
	}
}
