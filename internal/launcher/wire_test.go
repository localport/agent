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

// A client address is an IP literal without a zone and a port 1-65535; a
// probe carries none.
func TestValidateClientAddr(t *testing.T) {
	for addr, ok := range map[string]bool{
		"":                  true,
		"203.0.113.9:40022": true,
		"[2001:db8::7]:22":  true,
		"[fe80::1%eth0]:22": false,
		"203.0.113.9:0":     false,
		"203.0.113.9:70000": false,
		"203.0.113.9":       false,
		"host.example:22":   false,
		"203.0.113.9:22\n":  false,
	} {
		r := Request{V: Version, Kind: KindTerminal, Device: "team/device/t.p", Login: "pi", Cols: 80, Rows: 24, Term: "xterm", ClientAddr: addr}
		if err := r.Validate(); (err == nil) != ok || (err != nil && CodeOf(err) != CodeBadRequest) {
			t.Errorf("client address %q: %v, valid want %v", addr, err, ok)
		}
	}
	if err := (Request{V: Version, Kind: KindProbe, ClientAddr: "203.0.113.9:22"}).Validate(); CodeOf(err) != CodeBadRequest {
		t.Errorf("probe with a client address: %v, want bad_request", err)
	}
}

// A request of another version is refused as a version mismatch before its
// fields are checked, so a newer agent's unknown field does not hide it, and
// the client reports it as AG055 with the refusal still matchable.
func TestVersionMismatch(t *testing.T) {
	for _, body := range []string{`{"v":3,"kind":"terminal","future_field":1}`, `{"v":1,"kind":"probe"}`} {
		if _, err := decodeRequest([]byte(body)); CodeOf(err) != CodeVersionMismatch {
			t.Errorf("%s: %v, want version_mismatch", body, err)
		}
	}
	err := clientRefusal(CodeVersionMismatch, nil, "")
	if !errors.Is(err, ErrLauncherVersion) || CodeOf(err) != CodeVersionMismatch {
		t.Fatalf("client error %v", err)
	}
	if errors.Is(clientRefusal(CodeBusy, nil, ""), ErrLauncherVersion) {
		t.Fatal("busy reported as a version mismatch")
	}
}

// A Full Disk Access reading stands only beside Started or Refused and only
// with a known state.
func TestResponseFullDiskAccess(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp Response
		ok   bool
	}{
		{"started", Response{Started: &Started{SessionID: "s"}, FullDiskAccess: FullDiskAccessGranted}, true},
		{"refused", Response{Refused: &Refused{Code: CodeFullDiskAccessRequired}, FullDiskAccess: FullDiskAccessDenied}, true},
		{"none", Response{Started: &Started{SessionID: "s"}}, true},
		{"beside exit", Response{Exit: &Exit{}, FullDiskAccess: FullDiskAccessUnknown}, false},
		{"beside probe", Response{Probe: &Probe{}, FullDiskAccess: FullDiskAccessGranted}, false},
		{"unknown state", Response{Started: &Started{SessionID: "s"}, FullDiskAccess: "maybe"}, false},
	} {
		b, err := encode(tc.resp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readResponse(bytes.NewReader(b)); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// A started reply's view is checked where it enters the agent: home only
// beside confined, relative, clean, inside the served folder and within
// MaxFilesHome encoded; and only an sftp session may carry a view.
func TestResponseFilesView(t *testing.T) {
	if !ValidFilesHome(fullHome) || ValidFilesHome(fullHome+"<") {
		t.Fatal("MaxFilesHome bound misplaced")
	}
	for _, tc := range []struct {
		name string
		st   Started
		ok   bool
	}{
		{"none", Started{SessionID: "s"}, true},
		{"confined only", Started{SessionID: "s", Confined: true}, true},
		{"home equal", Started{SessionID: "s", Confined: true, Home: "."}, true},
		{"home below", Started{SessionID: "s", Confined: true, Home: "Users/x"}, true},
		{"home full", Started{SessionID: "s", Confined: true, Home: fullHome}, true},
		{"whole disk", Started{SessionID: "s", Confined: true, Home: "Users/x", WholeDisk: true}, true},
		{"whole disk without confined", Started{SessionID: "s", WholeDisk: true}, false},
		{"home without confined", Started{SessionID: "s", Home: "x"}, false},
		{"absolute", Started{SessionID: "s", Confined: true, Home: "/Users/x"}, false},
		{"parent", Started{SessionID: "s", Confined: true, Home: ".."}, false},
		{"above", Started{SessionID: "s", Confined: true, Home: "../x"}, false},
		{"unclean", Started{SessionID: "s", Confined: true, Home: "a/../b"}, false},
		{"trailing slash", Started{SessionID: "s", Confined: true, Home: "a/"}, false},
		{"nul", Started{SessionID: "s", Confined: true, Home: "a\x00b"}, false},
		{"too long", Started{SessionID: "s", Confined: true, Home: fullHome + "<"}, false},
	} {
		st := tc.st
		b, err := encode(Response{Started: &st})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := readResponse(bytes.NewReader(b)); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
	}
	view := Response{Started: &Started{SessionID: "s", Confined: true, Home: ".", WholeDisk: true}}
	if s, err := startedSession(nil, Request{Kind: KindSFTP}, view); err != nil || !s.Confined || s.Home != "." || !s.WholeDisk {
		t.Fatalf("sftp view: %+v, %v", s, err)
	}
	for _, kind := range []string{KindTerminal, KindExec, KindForward} {
		if _, err := startedSession(nil, Request{Kind: kind}, view); err == nil {
			t.Errorf("%s session accepted a files view", kind)
		}
		if _, err := startedSession(nil, Request{Kind: kind}, Response{Started: &Started{SessionID: "s", Confined: true}}); err == nil {
			t.Errorf("%s session accepted confined", kind)
		}
		if _, err := startedSession(nil, Request{Kind: kind}, Response{Started: &Started{SessionID: "s", WholeDisk: true}}); err == nil {
			t.Errorf("%s session accepted whole disk", kind)
		}
	}
}

// An end frame carries one known reason; any other payload is refused on
// both the write and the read.
func TestEndFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: FrameEnd, Data: []byte(EndFullDiskAccessRevoked)}); err != nil {
		t.Fatal(err)
	}
	f, err := NewFrameReader(&buf).ReadFrame()
	if err != nil || f.Type != FrameEnd || string(f.Data) != EndFullDiskAccessRevoked {
		t.Fatalf("read %+v, %v", f, err)
	}
	if err := WriteFrame(&buf, Frame{Type: FrameEnd, Data: []byte("other")}); err == nil {
		t.Fatal("an unknown end reason was written")
	}
	for _, payload := range []string{"other", "", strings.Repeat("x", maxEndReason+1)} {
		raw := append([]byte{FrameEnd, 0, 0, 0, byte(len(payload))}, payload...)
		if len(payload) > 255 {
			t.Fatal("payload too long for the one-byte length")
		}
		if _, err := NewFrameReader(bytes.NewReader(raw)).ReadFrame(); err == nil {
			t.Errorf("end frame %q was read", payload)
		}
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
