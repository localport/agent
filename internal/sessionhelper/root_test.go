//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
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
	os.Exit(m.Run())
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
	if err := launcher.WriteFrame(agentEnd, launcher.Frame{Type: launcher.FrameData, Data: []byte("echo WHO=$(id -un) PATH=$PATH; sh -c 'cd " + fdDir + " && echo FDS= * END'; exit 3\n")}); err != nil {
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
	m := regexp.MustCompile(`FDS= ([0-9 ]*) END`).FindStringSubmatch(out.String())
	if m == nil || len(strings.Fields(m[1])) != 4 {
		t.Fatalf("output %q: the shell holds descriptors beyond 0, 1, 2 and the listing's own", out.String())
	}
	agentEnd.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
}
