package errcode_test

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/tunnel"
)

// A coded error with a network cause shows its message and code only; the
// cause, with the endpoint it names, stays in Error() for --verbose.
func TestRenderLeavesOutANetworkCause(t *testing.T) {
	cause := &url.Error{Op: "Post", URL: "https://api.localport.io/v1/internal/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	err := fmt.Errorf("enrol: %w", errcode.New(errcode.NoTransport).With(cause, ""))
	text, hidden := errcode.Render(err)
	if text != errcode.New(errcode.NoTransport).Msg+" [AG071]" || !hidden {
		t.Fatalf("Render = %q, %v; want the message and code, cause hidden", text, hidden)
	}
	if full := err.Error(); !strings.Contains(full, "/v1/internal/x") || !strings.Contains(full, "connection refused") {
		t.Fatalf("Error() = %q, want the full chain", full)
	}
}

// A local file error the user acts on keeps its path and OS reason.
func TestRenderKeepsALocalPathError(t *testing.T) {
	dir := t.TempDir()
	_, cause := os.ReadFile(filepath.Join(dir, "missing.json"))
	err := errcode.New(errcode.InvalidLocalConfig).With(cause, "")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatal("the cause is not in the chain")
	}
	// The reason is the OS's own text for the errno ("no such file or
	// directory" on Unix, "The system cannot find the file specified." on
	// Windows).
	text, hidden := errcode.Render(err)
	want := "invalid local config: open " + filepath.Join(dir, "missing.json") + ": " + pathErr.Err.Error() + " [AG028]"
	if text != want || hidden {
		t.Fatalf("Render = %q, %v; want %q", text, hidden, want)
	}
	denied := errcode.New(errcode.InvalidLocalConfig).With(&fs.PathError{Op: "open", Path: "/etc/localport/agent.yaml", Err: syscall.EACCES}, "")
	want = "invalid local config: open /etc/localport/agent.yaml: " + syscall.EACCES.Error() + " [AG028]"
	if text, hidden := errcode.Render(denied); text != want || hidden {
		t.Fatalf("permission: Render = %q, %v; want %q", text, hidden, want)
	}
}

// Local input the user must fix prints in full under the agent error,
// nested context included; the cause stays in the chain.
func TestRenderShowsInvalidLocalInput(t *testing.T) {
	leaf := errcode.Invalidf("-L %s: device port must be 1-65535", "99999")
	err := errcode.New(errcode.AccessConfigInvalid).With(errcode.Invalidf("device %s: %w", "plc", leaf), "")
	want := errcode.New(errcode.AccessConfigInvalid).Msg + ": device plc: -L 99999: device port must be 1-65535 [AG122]"
	if text, hidden := errcode.Render(err); text != want || hidden {
		t.Fatalf("Render = %q, %v; want %q", text, hidden, want)
	}
	if !errors.Is(err, leaf) {
		t.Fatal("the leaf is not in the chain")
	}
}

// An Invalid built around a coded or network error renders that chain by
// type, so its codes stay separate and network text stays hidden.
func TestRenderInvalidAroundTypedErrors(t *testing.T) {
	coded := errcode.Invalidf("device %s: %w", "plc", errcode.New(errcode.RunLocked))
	if text, _ := errcode.Render(coded); text != errcode.New(errcode.RunLocked).Msg+" [AG021]" {
		t.Fatalf("coded: Render = %q", text)
	}
	network := errcode.Invalidf("fetch: %w", &url.Error{Op: "Get", URL: "https://x/v1/y", Err: errors.New("eof")})
	if text, hidden := errcode.Render(network); strings.Contains(text, "/v1/y") || !hidden {
		t.Fatalf("network: Render = %q, %v", text, hidden)
	}
}

// Detail is shown; a plain wrapper's words are not, and do not count as a
// hidden cause.
func TestRenderShowsDetailNotWrappers(t *testing.T) {
	err := fmt.Errorf("ssh-proxy: %w", errcode.New(errcode.NoSessionCert).With(nil, "run: localport ssh-cert pi gw"))
	if text, hidden := errcode.Render(err); text != "no session certificate: run: localport ssh-cert pi gw [AG101]" || hidden {
		t.Fatalf("Render = %q, %v", text, hidden)
	}
}

// The control plane's message and code print exactly as received, without
// the endpoint or status, alone and wrapped by an agent error (both codes).
func TestRenderShowsTheServerMessageAndCode(t *testing.T) {
	api := &identity.APIError{Path: "/v1/devices/renew", Status: 403, Code: "SE031", Message: "device removed from the team"}
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"alone":        {fmt.Errorf("renew: %w", api), "device removed from the team [SE031]"},
		"under AG":     {errcode.New(errcode.NotRenewable).With(api, ""), errcode.New(errcode.NotRenewable).Msg + ": device removed from the team [SE031] [AG007]"},
		"no message":   {&identity.APIError{Path: "/v1/x", Status: 503}, "the control plane failed to answer the request (HTTP 5xx)"},
		"code, no msg": {&identity.APIError{Path: "/v1/x", Status: 409, Code: "SE040"}, "the control plane refused the request (HTTP 4xx) [SE040]"},
	} {
		t.Run(name, func(t *testing.T) {
			text, _ := errcode.Render(tc.err)
			if text != tc.want {
				t.Fatalf("Render = %q, want %q", text, tc.want)
			}
			if strings.Contains(text, "/v1/") || strings.Contains(text, "403") {
				t.Fatalf("Render = %q names the endpoint or status", text)
			}
		})
	}
}

// An edge refusal prints its message and code; a local failure after it
// shows only when coded.
func TestRenderShowsAnEdgeRefusal(t *testing.T) {
	refusal := &tunnel.RegistrationError{Message: "tunnel limit reached", Code: "ED012"}
	if text, _ := errcode.Render(fmt.Errorf("run: %w", refusal)); text != "tunnel limit reached [ED012]" {
		t.Fatalf("Render = %q", text)
	}
	refusal.Err = errcode.New(errcode.RenewalInProgress)
	if text, _ := errcode.Render(refusal); text != "tunnel limit reached: another process is renewing this credential [AG006] [ED012]" {
		t.Fatalf("with a coded cause: Render = %q", text)
	}
	refusal.Err = &url.Error{Op: "Post", URL: "https://api.localport.io/v1/renew", Err: errors.New("timeout")}
	if text, hidden := errcode.Render(refusal); text != "tunnel limit reached [ED012]" || !hidden {
		t.Fatalf("with a network cause: Render = %q, %v", text, hidden)
	}
	if !strings.Contains(refusal.Error(), "timeout") {
		t.Fatalf("Error() = %q, want the cause for logs", refusal.Error())
	}
}

// A remedy a caller adds prints after the error and its codes, also when the
// error it wraps is a plain chain.
func TestRenderRemedy(t *testing.T) {
	err := fmt.Errorf("up: %w", errcode.WithRemedy(errcode.New(errcode.RunLocked).With(nil, "run.lock is held"), "run the device in the foreground with --foreground"))
	want := "localport is already running the devices of this config: run.lock is held [AG021]\n  run the device in the foreground with --foreground"
	if text, _ := errcode.Render(err); text != want {
		t.Fatalf("Render = %q, want %q", text, want)
	}
	if text, _ := errcode.Render(errcode.WithRemedy(errors.New("plain"), "do this")); text != "plain\n  do this" {
		t.Fatalf("plain: Render = %q", text)
	}
}

// A local OS error is shown; the same error inside a network failure is not.
func TestRenderOSErrors(t *testing.T) {
	local := errcode.New(errcode.InstallNotCommitted).With(fmt.Errorf("move: %w", os.NewSyscallError("rename", syscall.EACCES)), "")
	if text, hidden := errcode.Render(local); text != errcode.New(errcode.InstallNotCommitted).Msg+": rename: "+syscall.EACCES.Error()+" [AG084]" || hidden {
		t.Fatalf("local: Render = %q, %v", text, hidden)
	}
	remote := errcode.New(errcode.NoTransport).With(&net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, "")
	if text, hidden := errcode.Render(remote); strings.Contains(text, "192.0.2.1") || strings.Contains(text, "refused") || !hidden {
		t.Fatalf("network: Render = %q, %v", text, hidden)
	}
}

// A listen address in use is a local cause the user acts on.
func TestRenderKeepsAListenAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, lerr := net.Listen("tcp", ln.Addr().String())
	if lerr == nil {
		t.Skip("the platform allowed a second listener")
	}
	text, _ := errcode.Render(errcode.New(errcode.PortRefused).With(lerr, ""))
	if !strings.Contains(text, "listen "+ln.Addr().String()+": address already in use") {
		t.Fatalf("Render = %q", text)
	}
}

// Each error of a join prints on its own line with its own codes; under an
// agent error the branches are indented below it.
func TestRenderJoinedErrors(t *testing.T) {
	first := errcode.New(errcode.RunLocked).With(nil, "run.lock is held")
	second := errcode.New(errcode.InvalidLocalConfig).With(errcode.Invalidf("device x is listed twice"), "")
	want := first.Msg + ": run.lock is held [AG021]\n" + second.Msg + ": device x is listed twice [AG028]"
	if text, hidden := errcode.Render(errors.Join(first, second)); text != want || hidden {
		t.Fatalf("top level: Render = %q, %v; want %q", text, hidden, want)
	}
	nested := errcode.New(errcode.NoTransport).With(errors.Join(first, errors.New("internal")), "")
	want = errcode.New(errcode.NoTransport).Msg + " [AG071]\n  " + first.Msg + ": run.lock is held [AG021]"
	if text, hidden := errcode.Render(nested); text != want || !hidden {
		t.Fatalf("nested: Render = %q, %v; want %q and a hidden cause", text, hidden, want)
	}
}

// A plain chain prints as Error(), unless it holds a network error.
func TestRenderPlainChains(t *testing.T) {
	if text, hidden := errcode.Render(errors.New("name the device to change")); text != "name the device to change" || hidden {
		t.Fatalf("plain: Render = %q, %v", text, hidden)
	}
	netErr := fmt.Errorf("fetch: %w", &url.Error{Op: "Get", URL: "https://x/v1/y", Err: errors.New("eof")})
	if text, hidden := errcode.Render(netErr); text != "a network operation failed" || !hidden {
		t.Fatalf("network: Render = %q, %v", text, hidden)
	}
}

// The account codes name this platform's agent account: _localport on macOS,
// localport elsewhere.
func TestAccountCodesNameThePlatformAccount(t *testing.T) {
	account := "localport"
	if runtime.GOOS == "darwin" {
		account = "_localport"
	}
	for code, want := range map[errcode.Code]string{
		errcode.AccountMissing:     "the agent account " + account + " does not exist; create it with: sudo localport service install [AG137]",
		errcode.AccountNotChanged:  "the agent account " + account + " could not be created, looked up or inspected [AG138]",
		errcode.AgentGroupMissing:  "the group " + account + " does not exist; create it with: sudo localport service install [AG140]",
		errcode.AgentChildStart:    "localport could not start itself as the agent account " + account + " [AG038]",
		errcode.AgentAccountUnsafe: "the agent account " + account + " can log in or reaches other users' files; remove it, then run: sudo localport service install: it is a member of staff [AG147]",
	} {
		detail := ""
		if code == errcode.AgentAccountUnsafe {
			detail = "it is a member of staff"
		}
		if text, _ := errcode.Render(errcode.New(code).With(nil, detail)); text != want {
			t.Errorf("%s: Render = %q, want %q", code, text, want)
		}
	}
}
