//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// TestMain runs this test binary as the helper when started with the
// launcher's helper argv.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "helper" {
		os.Exit(Run(log.New(os.Stderr, "", 0).Printf))
	}
	if len(os.Args) == 2 && os.Args[1] == ForwardServerMode {
		if err := RunForwardServer(log.New(os.Stderr, "", 0).Printf); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestRootHelperForwardsAsTheLogin starts a forward helper as the launcher
// does, as root, for LOCALPORT_TEST_LOGIN, then dials and listens through
// it: the listener's socket file belongs to the login, so the forward
// server runs with the login's credentials, not root's.
func TestRootHelperForwardsAsTheLogin(t *testing.T) {
	login := os.Getenv("LOCALPORT_TEST_LOGIN")
	switch {
	case os.Geteuid() != 0:
		t.Skip("needs root")
	case login == "":
		t.Skip("set LOCALPORT_TEST_LOGIN to a test account")
	}
	u, err := user.Lookup(login)
	if err != nil {
		t.Fatal(err)
	}
	// The forward server is this binary run as the login, which cannot
	// reach the go-build directory: run a copy the login can execute.
	dir, err := os.MkdirTemp("/tmp", "lpfwroot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	copyExe := filepath.Join(dir, "localport-session")
	if err := os.WriteFile(copyExe, bin, 0o755); err != nil {
		t.Fatal(err)
	}

	agentEnd, helperEnd, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	cmd := &exec.Cmd{Path: copyExe, Args: []string{"localport-session", "helper"}, Env: []string{}, Dir: "/", Stderr: os.Stderr, ExtraFiles: []*os.File{helperEnd, theirs}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helperEnd.Close()
	theirs.Close()
	if err := launcher.WriteHelperRequest(ours, launcher.HelperRequest{Kind: launcher.KindForward, Login: login}); err != nil {
		t.Fatal(err)
	}
	reply, err := launcher.ReadHelperReply(ours)
	if err != nil || !reply.Started {
		t.Fatalf("helper reply %+v, %v", reply, err)
	}
	client, err := launcher.NewForwardClient(agentEnd, t.Logf)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	echo(t, ln)
	conn, err := client.Dial(ctx(t), launcher.FwdTCP, "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), "")
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, conn)
	_ = conn.Close()

	path := filepath.Join(dir, "r.sock")
	if _, _, err := client.Listen(ctx(t), launcher.FwdUnix, 0, false, path, func(a launcher.Accepted) { _ = a.Conn.Close() }, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if owner := strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Uid), 10); owner != u.Uid {
		t.Fatalf("socket owner uid %s, want the login's %s", owner, u.Uid)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600", perm)
	}

	_ = client.Close()
	<-client.Done()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket file after the helper's end: %v", err)
	}
}

// TestRootHelperRunsAPAMSession starts the helper as the launcher does, as
// root, for LOCALPORT_TEST_LOGIN (an account with /bin/sh), through the
// host's /etc/pam.d/localport, and runs a command in the login's shell. CI
// runs it under `make test-root` with the packaged PAM file installed.
func TestRootHelperRunsAPAMSession(t *testing.T) {
	login := os.Getenv("LOCALPORT_TEST_LOGIN")
	switch {
	case os.Geteuid() != 0:
		t.Skip("needs root")
	case login == "":
		t.Skip("set LOCALPORT_TEST_LOGIN to a test account")
	}
	if pamAvailable {
		if _, err := os.Stat("/etc/pam.d/localport"); err != nil {
			t.Fatalf("the PAM service file: %v", err)
		}
	}
	agentEnd, helperEnd, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer agentEnd.Close()
	ours, theirs, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Path: exe, Args: []string{"localport-session", "helper"}, Env: []string{}, Dir: "/", Stderr: os.Stderr, ExtraFiles: []*os.File{helperEnd, theirs}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helperEnd.Close()
	theirs.Close()
	defer cmd.Wait()

	if err := launcher.WriteHelperRequest(ours, launcher.HelperRequest{Kind: launcher.KindTerminal, Login: login, Cols: 80, Rows: 24, Term: "xterm"}); err != nil {
		t.Fatal(err)
	}
	reply, err := launcher.ReadHelperReply(ours)
	if err != nil || !reply.Started {
		t.Fatalf("helper reply %+v, %v", reply, err)
	}

	_ = agentEnd.SetDeadline(time.Now().Add(20 * time.Second))
	fdDir := "/dev/fd"
	if runtime.GOOS == "linux" {
		fdDir = "/proc/self/fd"
	}
	// The listing's own sh holds one descriptor beyond 0-2; the helper's
	// channel (3) and control (4) must not reach the shell.
	if err := launcher.WriteFrame(agentEnd, launcher.Frame{Type: launcher.FrameData, Data: []byte("echo WHO=$(id -un) PATH=$PATH; echo GROUPS=$(id -G) END; sh -c 'cd " + fdDir + " && echo FDS= * END'; exit 3\n")}); err != nil {
		t.Fatal(err)
	}
	fr := launcher.NewFrameReader(agentEnd)
	var out strings.Builder
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("channel ended: %v; output %q", err, out.String())
		}
		if f.Type == launcher.FrameExit {
			if f.Code != 3 {
				t.Fatalf("exit %d, want 3; output %q", f.Code, out.String())
			}
			break
		}
		out.Write(f.Data)
	}
	if !regexp.MustCompile(`WHO=` + regexp.QuoteMeta(login) + ` PATH=/`).MatchString(out.String()) {
		t.Fatalf("output %q: the shell did not run as %s with a PATH", out.String(), login)
	}
	// The shell holds the login's own groups, none of the helper's root groups.
	u, err := user.Lookup(login)
	if err != nil {
		t.Fatal(err)
	}
	want, err := u.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	g := regexp.MustCompile(`GROUPS=([0-9 ]*) END`).FindStringSubmatch(out.String())
	if g == nil {
		t.Fatalf("output %q: no group list", out.String())
	}
	got := strings.Fields(g[1])
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(slices.Compact(got), slices.Compact(want)) {
		t.Fatalf("the shell's groups are %v, want the login's %v", got, want)
	}
	m := regexp.MustCompile(`FDS= ([0-9 ]*) END`).FindStringSubmatch(out.String())
	if m == nil || len(strings.Fields(m[1])) != 4 {
		t.Fatalf("output %q: the shell holds descriptors beyond 0, 1, 2 and the listing's own", out.String())
	}
	agentEnd.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}
