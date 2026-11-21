//go:build cgo && darwin

package sessionhelper

/*
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>

extern char **environ;

typedef int (*lp_disclaim_fn)(posix_spawnattr_t *, int);

// lp_disclaim resolves responsibility_spawnattrs_setdisclaim, an exported
// libsystem symbol without a public header; NULL when this macOS lacks it.
static lp_disclaim_fn lp_disclaim(void) {
	return (lp_disclaim_fn)dlsym(RTLD_DEFAULT, "responsibility_spawnattrs_setdisclaim");
}

// lp_shell_exec replaces this process with path (argv), its own responsible
// process for TCC: POSIX_SPAWN_SETEXEC keeps the pid, session, controlling
// terminal, credentials and working directory; the mask is emptied, every
// catchable signal reset to its default, and only descriptors 0 to 2 stay
// open. It returns only on failure: the errno, with *step naming the call.
// fail_at > 0 fails that step with EINVAL before making it (tests).
static int lp_shell_exec(const char *path, char *const argv[], int fail_at, int *step) {
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t actions;
	sigset_t none, all;
	int rc = 0, have_attr = 0, have_actions = 0;
	lp_disclaim_fn disclaim = lp_disclaim();

#define LP_STEP(n, call) do { *step = (n); if (fail_at == (n)) { rc = EINVAL; goto out; } rc = (call); if (rc != 0) goto out; } while (0)
	if (disclaim == NULL) {
		*step = 0;
		return ENOSYS;
	}
	LP_STEP(1, posix_spawnattr_init(&attr));
	have_attr = 1;
	LP_STEP(2, posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT));
	sigemptyset(&none);
	LP_STEP(3, posix_spawnattr_setsigmask(&attr, &none));
	sigfillset(&all);
	sigdelset(&all, SIGKILL);
	sigdelset(&all, SIGSTOP);
	LP_STEP(4, posix_spawnattr_setsigdefault(&attr, &all));
	LP_STEP(5, posix_spawn_file_actions_init(&actions));
	have_actions = 1;
	LP_STEP(6, posix_spawn_file_actions_addinherit_np(&actions, 0));
	LP_STEP(7, posix_spawn_file_actions_addinherit_np(&actions, 1));
	LP_STEP(8, posix_spawn_file_actions_addinherit_np(&actions, 2));
	LP_STEP(9, disclaim(&attr, 1));
	LP_STEP(10, posix_spawn(NULL, path, &actions, &attr, argv, environ));
	// posix_spawn with POSIX_SPAWN_SETEXEC returns only on failure.
	if (rc == 0) rc = EINVAL;
#undef LP_STEP
out:
	if (have_actions) posix_spawn_file_actions_destroy(&actions);
	if (have_attr) posix_spawnattr_destroy(&attr);
	return rc;
}
*/
import "C"

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"
)

// shellExecSteps names lp_shell_exec's steps for its error line.
var shellExecSteps = []string{
	"responsibility_spawnattrs_setdisclaim unavailable",
	"posix_spawnattr_init", "posix_spawnattr_setflags", "posix_spawnattr_setsigmask",
	"posix_spawnattr_setsigdefault", "posix_spawn_file_actions_init",
	"posix_spawn_file_actions_addinherit_np 0", "posix_spawn_file_actions_addinherit_np 1",
	"posix_spawn_file_actions_addinherit_np 2", "responsibility_spawnattrs_setdisclaim", "posix_spawn",
}

// shellExecFailAt, when above zero, fails that lp_shell_exec step. Tests set it.
var shellExecFailAt int

// disclaimAvailable reports whether this macOS can start a process as its
// own responsible process.
func disclaimAvailable() bool { return C.lp_disclaim() != nil }

// ShellExec is the shell-exec mode; args are the shell's path, argv[0] and
// arguments. It replaces this process with the shell as its own responsible
// process, so TCC attributes the shell's file access to the shell (an Apple
// binary gets a silent EPERM on protected folders) and never prompts the
// console user for Localport. On failure it writes shellStartFailedLine to
// stderr, the step and errno to startLog, and returns 127.
func ShellExec(args []string, stderr, startLog io.Writer) int {
	if len(args) < 2 {
		return shellExecFailed(stderr, startLog, "usage: shell-exec <path> <argv0> [args...]")
	}
	path := C.CString(args[0])
	argv := make([]*C.char, len(args))
	for i, a := range args[1:] {
		argv[i] = C.CString(a)
	}
	defer func() {
		C.free(unsafe.Pointer(path))
		for _, a := range argv {
			C.free(unsafe.Pointer(a))
		}
	}()
	var step C.int
	rc := C.lp_shell_exec(path, &argv[0], C.int(shellExecFailAt), &step)
	name := "posix_spawn"
	if int(step) < len(shellExecSteps) {
		name = shellExecSteps[step]
	}
	return shellExecFailed(stderr, startLog, fmt.Sprintf("%s: %v", name, syscall.Errno(rc)))
}

// shellExecFailed writes the fixed line to stderr and detail to startLog, best
// effort, and returns 127.
func shellExecFailed(stderr, startLog io.Writer, detail string) int {
	_, _ = io.WriteString(stderr, shellStartFailedLine)
	_, _ = fmt.Fprintf(startLog, "shell-exec: %s\n", detail)
	return 127
}
