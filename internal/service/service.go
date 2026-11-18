// Package service installs, restarts and removes the fleet device service and
// the session launcher beside it: systemd units, OpenRC or OpenWrt procd init
// scripts on Linux, launchd daemons on macOS and Windows services. It is the
// single source of their definitions and of the Windows Event Log source. The
// device service definitions run `<binary> run --service` and the launcher
// definitions run `<session binary> launcher`. Service managers run by
// absolute path, never through PATH.
//
// A definition this package writes carries Marker. An existing file or
// Windows service under the same name without it belongs to someone else and
// is never overwritten or removed (ErrForeignUnit).
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
)

// Marker identifies a service definition this package wrote.
const Marker = "Managed by localport up; localport service uninstall removes it."

// StopBudget is how long every service manager lets the agent stop after
// SIGTERM, a Windows stop or a Windows preshutdown before it kills it. It
// exceeds tunnel.StopBound, the agent's longest graceful stop.
const StopBudget = 30 * time.Second

// stopBudgetSeconds is StopBudget as the integer the definitions carry.
const stopBudgetSeconds = int(StopBudget / time.Second)

// Manager controls the device service of one platform.
type Manager interface {
	// Name is the service's name in its service manager.
	Name() string
	// Check refuses, with ErrForeignUnit, when a definition under the
	// service's name exists without Marker. It returns the drop-in files
	// that extend the definition (systemd only), which install accepts and
	// lists. It changes nothing.
	Check() (dropIns []string, err error)
	// Installed reports whether a definition carrying Marker exists.
	Installed() (bool, error)
	// MainPID is the process ID of the service's main process while the
	// manager reports it running, and 0 otherwise: stopped, not installed,
	// or in a transient state (starting, stopping, waiting to restart).
	MainPID(ctx context.Context) (int, error)
	// Install writes the definition running exe, enables the service and
	// starts it, or restarts it when it already runs.
	Install(ctx context.Context, exe string) error
	// Restart restarts the installed service.
	Restart(ctx context.Context) error
	// Reload makes the running service re-read its config: SIGHUP on Linux
	// and macOS, SERVICE_CONTROL_PARAMCHANGE on Windows.
	Reload(ctx context.Context) error
	// Uninstall stops the service and removes its definition. It returns
	// ErrNotInstalled when there is none.
	Uninstall(ctx context.Context) error
}

var (
	// ErrForeignUnit refuses a definition under the device service's name
	// that this package did not write.
	ErrForeignUnit = errcode.New(errcode.ForeignUnit)
	// ErrNotInstalled means no device service is installed.
	ErrNotInstalled = errcode.New(errcode.NotInstalled)
	// ErrUnsupported means this platform has no service manager the agent
	// installs into.
	ErrUnsupported = errcode.New(errcode.Unsupported)
	// ErrMarkedForDelete means the Windows device service is deleted but
	// stays registered until every handle to it closes.
	ErrMarkedForDelete = errcode.New(errcode.MarkedForDelete)
	// ErrUnsafeExecutable refuses an executable path the definition cannot
	// carry verbatim. It is security.ErrUnsafeExecutable, which also refuses
	// a binary someone other than root could replace.
	ErrUnsafeExecutable = security.ErrUnsafeExecutable

	// errManager is a service manager command, query or call that failed.
	errManager = errcode.New(errcode.ServiceManagerFailed)
	// errDefinition is a definition file that could not be read, written or
	// removed.
	errDefinition = errcode.New(errcode.ServiceDefinitionFailed)
)

// ExitRunLocked is the exit status of `run --service` when run.lock stays
// held past its wait. It differs from a failure (1), so a restart that only
// overlapped the previous process is not counted as a crash.
const ExitRunLocked = 3

// ExitError ends the process with Code: the process exit status, or the
// Windows service-specific exit code under the service control manager.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

// CommandError is a failed command: a service manager command or an account
// tool (useradd, adduser, dscl).
type CommandError struct {
	Command string
	// ExitCode is the command's exit status, or -1 when it did not exit
	// (not found, timed out).
	ExitCode int
	Output   string
	Err      error
}

func (e *CommandError) Error() string {
	if e.Output == "" {
		return fmt.Sprintf("%s: %v", e.Command, e.Err)
	}
	return fmt.Sprintf("%s: %v: %s", e.Command, e.Err, e.Output)
}

func (e *CommandError) Unwrap() error { return e.Err }

// commandTimeout bounds each command, so a hung systemctl, launchctl or
// useradd never stalls up, set or uninstall.
const commandTimeout = 60 * time.Second

// runner runs one service manager or account tool command, given by absolute
// path, and returns its standard output; tests replace it.
type runner func(ctx context.Context, name string, args ...string) (string, error)

func execRun(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), nil
	}
	code := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		code = exitErr.ExitCode()
	}
	output := strings.TrimSpace(stderr.String())
	if output == "" {
		output = strings.TrimSpace(stdout.String())
	}
	return "", &CommandError{
		Command:  strings.Join(append([]string{name}, args...), " "),
		ExitCode: code,
		Output:   output,
		Err:      err,
	}
}

// managerRun is execRun for the service managers: a failed command is AG135
// with the command as detail. The account tools use execRun, under AG138.
func managerRun(ctx context.Context, name string, args ...string) (string, error) {
	out, err := execRun(ctx, name, args...)
	var cmdErr *CommandError
	if errors.As(err, &cmdErr) {
		return out, errManager.With(err, cmdErr.Command)
	}
	return out, err
}

// Executable is the real path of the running binary, every symlink resolved:
// the file the service definition runs and security.CheckServiceBinary
// checks. A package manager's link is not kept, because the check must judge
// the file that actually executes.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", errcode.New(errcode.ExecutableUnknown).With(err, "")
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", errcode.New(errcode.ExecutableUnknown).With(err, exe)
	}
	return filepath.Abs(real)
}

// AgentAccount is the system account the device service runs as on this
// platform. Each service definition names its own platform's account
// (agentaccount.Linux or agentaccount.MacOS), so it renders the same on
// every build.
const AgentAccount = launcher.AgentAccount

// AgentLogDir is the agent's own log directory under launchd and OpenRC,
// owned by AgentAccount.
const AgentLogDir = "/var/log/localport"

// SessionExecutable is the session launcher binary, localport-session (with
// exe's extension, .exe on Windows), installed beside the agent executable
// exe.
func SessionExecutable(exe string) string {
	return filepath.Join(filepath.Dir(exe), "localport-session"+filepath.Ext(exe))
}

// owned reports whether path exists, and refuses one without Marker.
func owned(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errDefinition.With(err, "read "+path)
	}
	if !bytes.Contains(content, []byte(Marker)) {
		return true, ErrForeignUnit.With(nil, fmt.Sprintf("%s; move it aside or remove it, then run the command again", path))
	}
	return true, nil
}

// checkOwned refuses, before anything is written, when any of paths exists
// without Marker, so an install never leaves a partial set of definitions.
func checkOwned(paths ...string) error {
	for _, p := range paths {
		if _, err := owned(p); err != nil {
			return err
		}
	}
	return nil
}

// writeOwned replaces path with content, mode 0644, after owned accepts it.
func writeOwned(path string, content []byte) error { return writeOwnedMode(path, content, 0o644) }

// writeOwnedMode replaces path with content and mode after owned accepts it.
// The write goes through a temporary file in the same directory and a rename,
// so the service manager never reads a partial definition.
func writeOwnedMode(path string, content []byte, mode os.FileMode) error {
	if _, err := owned(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".localport-device-*")
	if err != nil {
		return errDefinition.With(err, "write "+path)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return errDefinition.With(err, "write "+path)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return errDefinition.With(err, "write "+path)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return errDefinition.With(err, "write "+path)
	}
	if err := tmp.Close(); err != nil {
		return errDefinition.With(err, "write "+path)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errDefinition.With(err, "write "+path)
	}
	return nil
}

// removeOwned deletes path after owned accepts it; ErrNotInstalled when it
// does not exist.
func removeOwned(path string) error {
	exists, err := owned(path)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotInstalled
	}
	if err := os.Remove(path); err != nil {
		return errDefinition.With(err, "remove "+path)
	}
	return nil
}
