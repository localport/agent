//go:build cgo && darwin

package sessionhelper

import (
	"bytes"
	"fmt"
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
// a caller of the mode could leave them, then runs the mode as a helper
// starts it, its start log open as descriptor 3 (ExtraFiles); exec'd, the
// probe reports what the shell got.
func runShellExecChild() int {
	runtime.LockOSThread()
	signal.Ignore(syscall.SIGHUP)
	if err := testsys.Block(syscall.SIGUSR2); err != nil {
		os.Stderr.WriteString(err.Error())
		return 3
	}
	return ShellExecMain([]string{"/bin/sh", "sh", "-c", shellExecProbe})
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

// Each failing step of the mode returns 127 without starting anything (this
// process is still here to check): the session's stderr gets only the fixed
// coded line, and the start log one line naming the step and its errno.
func TestShellExecFailsClosed(t *testing.T) {
	if !disclaimAvailable() {
		t.Skip("this macOS has no responsibility_spawnattrs_setdisclaim")
	}
	t.Cleanup(func() { shellExecFailAt = 0 })
	check := func(name string, args []string, wantLog string) {
		t.Helper()
		var stderr, startLog bytes.Buffer
		if code := ShellExec(args, &stderr, &startLog); code != 127 {
			t.Fatalf("%s: exit %d, want 127", name, code)
		}
		if stderr.String() != shellStartFailedLine {
			t.Errorf("%s: stderr %q, want only %q", name, stderr.String(), shellStartFailedLine)
		}
		if !strings.HasPrefix(startLog.String(), wantLog) || strings.Count(startLog.String(), "\n") != 1 {
			t.Errorf("%s: start log %q, want one line starting %q", name, startLog.String(), wantLog)
		}
	}
	for step := 1; step < len(shellExecSteps); step++ {
		shellExecFailAt = step
		check(fmt.Sprintf("step %d", step), []string{"/bin/sh", "sh", "-c", "exit 0"}, "shell-exec: "+shellExecSteps[step]+": ")
	}
	shellExecFailAt = 0
	check("too few arguments", []string{"/bin/sh"}, "shell-exec: usage: ")
}
