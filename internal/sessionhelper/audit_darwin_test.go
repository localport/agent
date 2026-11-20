//go:build cgo && darwin

package sessionhelper

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/sessionhelper/testsys"
)

// auditProbeEnv makes this test binary print its audit session and exit.
const auditProbeEnv = "LOCALPORT_TEST_AUDIT_PROBE"

func runAuditProbe() int {
	auid, flags, err := testsys.Audit()
	if err != nil {
		fmt.Println("AUDIT error", err)
		return 1
	}
	fmt.Printf("AUDIT auid=%d remote=%v authenticated=%v tty=%v END\n", auid,
		flags&testsys.AuditIsRemote != 0, flags&testsys.AuditHasAuthenticated != 0, flags&testsys.AuditHasTTY != 0)
	return 0
}

// A terminal session's processes run in the login's own remote audit
// session, as under Apple's sshd: the audit user id is the login's, and the
// session is remote, authenticated and has a TTY.
func TestRootHelperAuditSession(t *testing.T) {
	login := rootLogin(t)
	u, err := user.Lookup(login)
	if err != nil {
		t.Fatal(err)
	}
	// The probe runs as the login, which cannot reach the go-build directory.
	dir, err := os.MkdirTemp("/tmp", "lpaudit")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
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
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	req := launcher.HelperRequest{Kind: launcher.KindTerminal, Login: login, Cols: 80, Rows: 24, Term: "xterm", ClientAddr: "203.0.113.9:40022"}
	out, code := runRootTerminal(t, req, auditProbeEnv+"=1 "+probe+"; exit 0\n")
	if code != 0 {
		t.Fatalf("exit %d; output %q", code, out)
	}
	if want := "AUDIT auid=" + u.Uid + " remote=true authenticated=true tty=true END"; !strings.Contains(out, want) {
		t.Fatalf("output %q, want %q", out, want)
	}
}
