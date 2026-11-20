//go:build cgo && linux

package sessionhelper

// shellExecChildEnv names the shell-exec child mode, which exists on macOS
// only; runShellExecChild never runs here.
const shellExecChildEnv = "LOCALPORT_TEST_SHELL_EXEC"

func runShellExecChild() int { return 2 }
