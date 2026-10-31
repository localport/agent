//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
)

// TestMain runs this test binary as a fake helper when the launcher starts it
// with the helper's argv: it answers started, writes one data frame and an
// exit frame on the channel, and exits.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "helper" {
		os.Exit(fakeHelper())
	}
	os.Exit(m.Run())
}

func fakeHelper() int {
	channel, control := os.NewFile(3, "channel"), os.NewFile(4, "control")
	req, err := ReadHelperRequest(control)
	if err != nil {
		return 1
	}
	if req.Login == "refuse" {
		_ = WriteHelperReply(control, HelperReply{Refused: CodeAccountRefused})
		return 1
	}
	if err := WriteHelperReply(control, HelperReply{Started: true}); err != nil {
		return 1
	}
	_ = WriteFrame(channel, Frame{Type: FrameData, Data: []byte(req.Login + " " + req.Term)})
	_ = WriteFrame(channel, Frame{Type: FrameExit, Code: 7})
	return 0
}

const testDevice = "01kpq7x2abcd34/device/tun12345.gw-01"

func testConfig(t *testing.T, d config.LocalDevice) func() (*config.LocalConfig, error) {
	t.Helper()
	ref, err := identity.ParseDeviceRef(testDevice)
	if err != nil {
		t.Fatal(err)
	}
	d.Identity = ref
	return func() (*config.LocalConfig, error) { return &config.LocalConfig{Devices: []config.LocalDevice{d}}, nil }
}

// serve runs a launcher for uid on a fresh socket and returns its client.
func serve(t *testing.T, uid uint32, load func() (*config.LocalConfig, error)) (Client, *Server) {
	t.Helper()
	// macOS bounds a socket path at 104 bytes; t.TempDir is too deep.
	dir, err := os.MkdirTemp("/tmp", "lp-launcher-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		AgentUID: uid, AgentAccount: AgentAccount, LoadConfig: load, HelperPath: exe,
		Probe: func() Probe { return Probe{PAM: true, FullDiskAccess: FullDiskAccessDenied} },
		Log:   t.Logf,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
		s.wg.Wait()
	})
	return Client{Path: path}, s
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func terminalRequest(login string) Request {
	return Request{Kind: KindTerminal, Device: testDevice, Login: login, Cols: 80, Rows: 24, Term: "xterm-256color"}
}

func TestProbeAnswersTheAgentAccount(t *testing.T) {
	c, _ := serve(t, uint32(os.Getuid()), testConfig(t, config.LocalDevice{}))
	p, err := c.Probe(ctx(t))
	if err != nil || !p.PAM || p.FullDiskAccess != FullDiskAccessDenied {
		t.Fatalf("Probe = %+v, %v", p, err)
	}
}

// A peer whose uid is not the agent account gets no answer at all.
func TestPeerOtherThanTheAgentAccountIsRefused(t *testing.T) {
	c, _ := serve(t, uint32(os.Getuid())+1, testConfig(t, config.LocalDevice{}))
	if _, err := c.Probe(ctx(t)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Probe from another uid = %v, want ErrUnavailable", err)
	}
}

func TestStartRelaysTheHelpersChannel(t *testing.T) {
	c, _ := serve(t, uint32(os.Getuid()), testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"pi"}}))
	ours, theirs, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	sess, err := c.Start(ctx(t), terminalRequest("pi"), theirs)
	theirs.Close()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Close()
	if len(sess.ID) != 32 {
		t.Fatalf("session id %q", sess.ID)
	}
	_ = ours.SetDeadline(time.Now().Add(10 * time.Second))
	fr := NewFrameReader(ours)
	f, err := fr.ReadFrame()
	if err != nil || f.Type != FrameData || string(f.Data) != "pi xterm-256color" {
		t.Fatalf("first frame %+v, %v", f, err)
	}
	if f, err = fr.ReadFrame(); err != nil || f.Type != FrameExit || f.Code != 7 {
		t.Fatalf("second frame %+v, %v", f, err)
	}
	if e, err := sess.Wait(); err != nil || e.Status != 0 {
		t.Fatalf("Wait = %+v, %v", e, err)
	}
}

// Every config refusal comes before a helper starts, with its typed code.
func TestStartRefusesWhatTheConfigDoesNotEnable(t *testing.T) {
	terminal := []config.Capability{config.CapabilityTerminal}
	for _, tc := range []struct {
		name   string
		device config.LocalDevice
		req    Request
		code   string
	}{
		{"login not listed", config.LocalDevice{Enable: terminal, Logins: []string{"pi"}}, terminalRequest("root"), CodeLoginNotEnabled},
		{"kind not enabled", config.LocalDevice{Enable: []config.Capability{config.CapabilityFiles}, Logins: []string{"pi"}}, terminalRequest("pi"), CodeKindNotEnabled},
		{"unknown device", config.LocalDevice{Enable: terminal, Logins: []string{"pi"}}, func() Request {
			r := terminalRequest("pi")
			r.Device = "01kpq7x2abcd34/device/tun12345.other"
			return r
		}(), CodeDeviceUnknown},
		{"run_as_agent takes only the agent account", config.LocalDevice{Enable: terminal, RunAsAgent: true}, terminalRequest("pi"), CodeLoginNotEnabled},
		{"helper refusal", config.LocalDevice{Enable: terminal, Logins: []string{"refuse"}}, terminalRequest("refuse"), CodeAccountRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := serve(t, uint32(os.Getuid()), testConfig(t, tc.device))
			ours, theirs, err := SocketPair()
			if err != nil {
				t.Fatal(err)
			}
			defer ours.Close()
			_, err = c.Start(ctx(t), tc.req, theirs)
			theirs.Close()
			if got := CodeOf(err); got != tc.code {
				t.Fatalf("Start = %v, want code %s", err, tc.code)
			}
		})
	}
}

func TestRunAsAgentStartsTheAgentAccount(t *testing.T) {
	s := &Server{AgentAccount: AgentAccount, LoadConfig: testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, RunAsAgent: true})}
	h, err := s.authorize(terminalRequest(AgentAccount))
	if err != nil || !h.AgentAccount || h.Login != AgentAccount {
		t.Fatalf("authorize = %+v, %v", h, err)
	}
}

func TestRequestValidation(t *testing.T) {
	ok := terminalRequest("pi")
	ok.V = Version
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid request: %v", err)
	}
	for name, edit := range map[string]func(*Request){
		"old version":    func(r *Request) { r.V = 0 },
		"unknown kind":   func(r *Request) { r.Kind = "shell" },
		"no login":       func(r *Request) { r.Login = "" },
		"no device":      func(r *Request) { r.Device = "" },
		"zero cols":      func(r *Request) { r.Cols = 0 },
		"rows too large": func(r *Request) { r.Rows = 1001 },
		"bad term":       func(r *Request) { r.Term = "xterm;rm" },
	} {
		r := ok
		edit(&r)
		if CodeOf(r.Validate()) != CodeBadRequest {
			t.Errorf("%s: %v, want bad_request", name, r.Validate())
		}
	}
	for _, kind := range []string{KindExec, KindSFTP} {
		r := ok
		r.Kind = kind
		if CodeOf(r.Validate()) != CodeUnsupportedKind {
			t.Errorf("%s: %v, want unsupported_kind", kind, r.Validate())
		}
	}
	if err := (Request{V: Version, Kind: KindProbe, Login: "pi"}).Validate(); CodeOf(err) != CodeBadRequest {
		t.Errorf("probe with fields: %v, want bad_request", err)
	}
}

// An unknown field or trailing data in a request is refused.
func TestDecodeRequestIsStrict(t *testing.T) {
	for _, body := range []string{`{"v":1,"kind":"probe","env":"X"}`, `{"v":1,"kind":"probe"} {}`} {
		if _, err := decodeRequest([]byte(body)); CodeOf(err) != CodeBadRequest {
			t.Errorf("%s: %v, want bad_request", body, err)
		}
	}
}

func TestFrameRoundTripAndRefusals(t *testing.T) {
	var buf bytes.Buffer
	for _, f := range []Frame{{Type: FrameData, Data: []byte("hi")}, {Type: FrameResize, Cols: 120, Rows: 40}, {Type: FrameExit, Code: -1}} {
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	fr := NewFrameReader(&buf)
	if f, err := fr.ReadFrame(); err != nil || string(f.Data) != "hi" {
		t.Fatalf("data %+v, %v", f, err)
	}
	if f, err := fr.ReadFrame(); err != nil || f.Cols != 120 || f.Rows != 40 {
		t.Fatalf("resize %+v, %v", f, err)
	}
	if f, err := fr.ReadFrame(); err != nil || f.Code != -1 {
		t.Fatalf("exit %+v, %v", f, err)
	}
	if _, err := fr.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("end = %v, want EOF", err)
	}
	for name, raw := range map[string][]byte{
		"unknown type":     {9, 0, 0, 0, 0},
		"empty data":       {FrameData, 0, 0, 0, 0},
		"oversized data":   {FrameData, 0, 2, 0, 0},
		"short resize":     {FrameResize, 0, 0, 0, 2, 0, 1},
		"zero size resize": {FrameResize, 0, 0, 0, 4, 0, 0, 0, 0},
		"truncated":        {FrameData, 0, 0, 0, 5, 'a'},
	} {
		if _, err := NewFrameReader(bytes.NewReader(raw)).ReadFrame(); !errors.Is(err, errBadFrame) {
			t.Errorf("%s: %v, want errBadFrame", name, err)
		}
	}
	if err := WriteFrame(io.Discard, Frame{Type: FrameData}); !errors.Is(err, errBadFrame) {
		t.Errorf("empty data write: %v", err)
	}
}
