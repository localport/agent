package launcher

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"
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

// Only an sftp request carries the file access; any other kind with either
// flag is refused.
func TestValidateFilesAccess(t *testing.T) {
	sftp := Request{V: Version, Kind: KindSFTP, Device: "d", Login: "alice", FilesDownload: true, FilesUpload: true}
	if err := sftp.Validate(); err != nil {
		t.Fatalf("sftp with access: %v", err)
	}
	for _, r := range []Request{
		{V: Version, Kind: KindTerminal, Device: "d", Login: "alice", Cols: 80, Rows: 24, Term: "xterm", FilesDownload: true},
		{V: Version, Kind: KindExec, Device: "d", Login: "alice", Command: "id", FilesUpload: true},
		{V: Version, Kind: KindForward, Device: "d", Login: "alice", FilesUpload: true},
		{V: Version, Kind: KindProbe, FilesDownload: true},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s with file access: accepted", r.Kind)
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

// The request bound ends with the request: a later read on the conn waits for
// data instead of failing at the expired deadline.
func TestReadWithinClearsTheDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	const bound = 20 * time.Millisecond
	if err := readWithin(server, bound, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * bound)
	go func() { _, _ = client.Write([]byte{1}) }()
	if _, err := server.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read after the request bound = %v", err)
	}
}

// A stalled request read ends at the bound.
func TestReadWithinBoundsTheRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	err := readWithin(server, 20*time.Millisecond, func() error {
		_, err := server.Read(make([]byte, 1))
		return err
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("readWithin = %v, want the deadline error", err)
	}
}
