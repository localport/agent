//go:build linux || darwin

package launcher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
	switch req.Login {
	case "refuse":
		_ = WriteHelperReply(control, HelperReply{Refused: CodeAccountRefused})
		return 1
	case "slow-refuse":
		// A lookup or PAM account step slower than the request read bound.
		time.Sleep(requestTimeout + time.Second)
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

// openFDs counts this process's open descriptors.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// A request carrying more than one descriptor is a bad request: refused
// before the config is read or anything starts, with every received
// descriptor closed.
func TestRequestWithTwoDescriptorsIsRefused(t *testing.T) {
	c, _ := serve(t, uint32(os.Getuid()), testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"pi"}}))
	conn, err := c.dial(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	a, b, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	req := terminalRequest("pi")
	req.V = Version
	msg, err := encode(req)
	if err != nil {
		t.Fatal(err)
	}
	before := openFDs(t)
	if _, _, err := conn.WriteMsgUnix(msg, unix.UnixRights(int(a.Fd()), int(b.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	resp, err := readResponse(conn)
	if err != nil || resp.Refused == nil || resp.Refused.Code != CodeBadRequest {
		t.Fatalf("response %+v, %v; want refused %s", resp, err, CodeBadRequest)
	}
	// The server shares this process: descriptors it received and kept
	// would show here.
	if after := openFDs(t); after > before {
		t.Fatalf("open descriptors %d after the refusal, %d before: the received ones leaked", after, before)
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
		{"helper refusal after the request read bound", config.LocalDevice{Enable: terminal, Logins: []string{"slow-refuse"}}, terminalRequest("slow-refuse"), CodeAccountRefused},
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

// A file session needs files enabled, not terminal, and is confined to the
// device's files_root; a terminal session needs terminal.
func TestAuthorizeFileSessions(t *testing.T) {
	files := Request{V: Version, Kind: KindSFTP, Device: terminalRequest("pi").Device, Login: "pi"}
	s := &Server{LoadConfig: testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityFiles},
		Logins: []string{"pi"}, FilesRoot: "/srv/share"})}
	h, err := s.authorize(files)
	if err != nil || h.Kind != KindSFTP || h.Root != "/srv/share" {
		t.Fatalf("authorize = %+v, %v", h, err)
	}
	if _, err := s.authorize(terminalRequest("pi")); CodeOf(err) != CodeKindNotEnabled {
		t.Fatalf("terminal on a files-only device: %v, want kind_not_enabled", err)
	}
	s = &Server{LoadConfig: testConfig(t, config.LocalDevice{Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{"pi"}})}
	if _, err := s.authorize(files); CodeOf(err) != CodeKindNotEnabled {
		t.Fatalf("files on a terminal-only device: %v, want kind_not_enabled", err)
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
	// sftp: on pipes, no terminal and no command.
	r := ok
	r.Kind, r.Cols, r.Rows, r.Term = KindSFTP, 0, 0, ""
	if err := r.Validate(); err != nil {
		t.Errorf("sftp: %v", err)
	}
	for name, edit := range map[string]func(*Request){
		"sftp with a terminal": func(r *Request) { r.Cols, r.Rows, r.Term = 80, 24, "xterm" },
		"sftp with a command":  func(r *Request) { r.Command = "ls" },
	} {
		bad := r
		edit(&bad)
		if CodeOf(bad.Validate()) != CodeBadRequest {
			t.Errorf("%s: %v, want bad_request", name, bad.Validate())
		}
	}
	// env: LANG and LC_* within the bounds pass; the launcher refuses
	// anything else even when the agent sent it.
	withEnv := ok
	withEnv.Env = map[string]string{"LANG": "en_GB.UTF-8", "LC_TIME": "C"}
	if err := withEnv.Validate(); err != nil {
		t.Errorf("valid env: %v", err)
	}
	full := map[string]string{}
	for i := range MaxEnvVars {
		full[fmt.Sprintf("LC_V%c", 'A'+i)] = "C"
	}
	tooMany := maps.Clone(full)
	tooMany["LC_OVER"] = "C"
	big := map[string]string{}
	for i := range 5 {
		big[fmt.Sprintf("LC_B%c", 'A'+i)] = strings.Repeat("a", MaxEnvValue)
	}
	for name, env := range map[string]map[string]string{
		"PATH":            {"PATH": "/evil"},
		"LD_PRELOAD":      {"LD_PRELOAD": "x.so"},
		"control char":    {"LANG": "C\n"},
		"value too long":  {"LANG": strings.Repeat("a", MaxEnvValue+1)},
		"too many":        tooMany,
		"over 1 KiB":      big,
		"lower-case name": {"lc_all": "C"},
	} {
		r := ok
		r.Env = env
		if CodeOf(r.Validate()) != CodeBadRequest {
			t.Errorf("env %s: %v, want bad_request", name, r.Validate())
		}
	}
	if r := ok; func() bool { r.Env = full; return r.Validate() != nil }() {
		t.Errorf("%d variables refused", MaxEnvVars)
	}
	if r := ok; r.Validate() != nil || func() bool { r.Command = "id"; return CodeOf(r.Validate()) != CodeBadRequest }() {
		t.Error("a terminal request with a command was not refused")
	}
	// exec: with a PTY (the terminal's fields), or without one (no size and
	// no term); a command up to MaxCommand bytes of UTF-8 without NUL.
	execOK := ok
	execOK.Kind, execOK.Command = KindExec, "uname -a"
	noPTY := execOK
	noPTY.Cols, noPTY.Rows, noPTY.Term = 0, 0, ""
	shellNoPTY := noPTY
	shellNoPTY.Command = ""
	for name, r := range map[string]Request{"exec with a pty": execOK, "exec on pipes": noPTY, "login shell on pipes": shellNoPTY} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(*Request){
		"command too long":   func(r *Request) { r.Command = strings.Repeat("x", MaxCommand+1) },
		"command with NUL":   func(r *Request) { r.Command = "id\x00x" },
		"command not UTF-8":  func(r *Request) { r.Command = "\xff" },
		"half a size":        func(r *Request) { r.Rows = 0 },
		"term without size":  func(r *Request) { r.Cols, r.Rows = 0, 0 },
		"exec without login": func(r *Request) { r.Login = "" },
	} {
		r := execOK
		edit(&r)
		if CodeOf(r.Validate()) != CodeBadRequest {
			t.Errorf("exec %s: %v, want bad_request", name, r.Validate())
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
	for _, f := range []Frame{{Type: FrameData, Data: []byte("hi")}, {Type: FrameResize, Cols: 120, Rows: 40}, {Type: FrameExit, Code: -1},
		{Type: FrameStderr, Data: []byte("err")}, {Type: FrameEOF}} {
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
	if f, err := fr.ReadFrame(); err != nil || f.Type != FrameStderr || string(f.Data) != "err" {
		t.Fatalf("stderr %+v, %v", f, err)
	}
	if f, err := fr.ReadFrame(); err != nil || f.Type != FrameEOF || len(f.Data) != 0 {
		t.Fatalf("eof %+v, %v", f, err)
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
		"eof with payload": {FrameEOF, 0, 0, 0, 1, 'a'},
		"empty stderr":     {FrameStderr, 0, 0, 0, 0},
	} {
		if _, err := NewFrameReader(bytes.NewReader(raw)).ReadFrame(); !errors.Is(err, errBadFrame) {
			t.Errorf("%s: %v, want errBadFrame", name, err)
		}
	}
	if err := WriteFrame(io.Discard, Frame{Type: FrameData}); !errors.Is(err, errBadFrame) {
		t.Errorf("empty data write: %v", err)
	}
}
