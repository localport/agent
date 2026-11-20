//go:build cgo && darwin

package sessionhelper

import (
	"bytes"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/localport/agent/internal/sessionhelper/testsys"
)

// shellExecChildEnv makes this test binary run as a shell-exec child.
const shellExecChildEnv = "LOCALPORT_TEST_SHELL_EXEC"

// shellExecProbe prints whether SIGUSR2 reaches a child shell (blocked, the
// child survives it) and whether descriptor 3 is open, then survives SIGHUP
// only when ignored. macOS ps shows no sigmask, so it tests delivery.
const shellExecProbe = `if /bin/sh -c 'kill -USR2 $$'; then echo usr2-blocked; else echo usr2-delivered; fi; if [ -e /dev/fd/3 ]; then echo fd3-open; else echo fd3-closed; fi; kill -HUP $$; echo survived`

// runShellExecChild is the child: it ignores SIGHUP and blocks SIGUSR2, as
// a caller of the mode could leave them, then runs the mode with descriptor 3
// open (ExtraFiles); exec'd, the probe reports what the shell got.
func runShellExecChild() int {
	runtime.LockOSThread()
	signal.Ignore(syscall.SIGHUP)
	if err := testsys.Block(syscall.SIGUSR2); err != nil {
		os.Stderr.WriteString(err.Error())
		return 3
	}
	return ShellExec([]string{"/bin/sh", "sh", "-c", shellExecProbe}, os.Stderr)
}

// The shell the mode execs has an empty signal mask, every signal at its
// default disposition and only descriptors 0 to 2: SIGUSR2 reaches the
// probe's child, the probe sees no descriptor 3 (the start log does not
// reach the shell), and dies of the SIGHUP it sends itself.
func TestShellExecStartsTheShellClean(t *testing.T) {
	if !disclaimAvailable() {
		t.Skip("this macOS has no responsibility_spawnattrs_setdisclaim")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), shellExecChildEnv+"=1")
	cmd.ExtraFiles = []*os.File{w}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err = cmd.Run()
	w.Close()
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGHUP {
		t.Fatalf("shell ended %v (%v), want killed by SIGHUP; stdout %q stderr %q", cmd.ProcessState, err, out.String(), stderr.String())
	}
	lines := strings.Fields(out.String())
	if len(lines) != 2 || lines[0] != "usr2-delivered" || lines[1] != "fd3-closed" {
		t.Fatalf("probe printed %q, want usr2-delivered and fd3-closed", out.String())
	}
}

// Each failing step of the mode writes one line naming it and returns 127
// without starting anything; this process is still here to check.
func TestShellExecFailsClosed(t *testing.T) {
	if !disclaimAvailable() {
		t.Skip("this macOS has no responsibility_spawnattrs_setdisclaim")
	}
	t.Cleanup(func() { shellExecFailAt = 0 })
	for step := 1; step < len(shellExecSteps); step++ {
		shellExecFailAt = step
		var stderr bytes.Buffer
		if code := ShellExec([]string{"/bin/sh", "sh", "-c", "exit 0"}, &stderr); code != 127 {
			t.Fatalf("step %d: exit %d, want 127", step, code)
		}
		if want := "localport: shell-exec: " + shellExecSteps[step] + ": "; !strings.HasPrefix(stderr.String(), want) || strings.Count(stderr.String(), "\n") != 1 {
			t.Errorf("step %d: stderr %q, want one line starting %q", step, stderr.String(), want)
		}
	}
	var stderr bytes.Buffer
	if code := ShellExec([]string{"/bin/sh"}, &stderr); code != 127 {
		t.Fatalf("too few arguments: exit %d", code)
	}
}
