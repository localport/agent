// Package service installs, restarts and removes the fleet device service:
// the systemd unit localport-device.service on Linux, the launchd daemon
// io.localport.device on macOS and the Windows service localport-device. It is
// the single source of their definitions and of the Windows Event Log
// source. Every definition runs `<binary> run --service`. Service managers
// run by absolute path, never through PATH.
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
const Marker = "Managed by localport connect; localport service uninstall removes it."

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
	// Stop stops the agent service and returns once it has stopped; the
	// launcher keeps running. Install starts it again.
	Stop(ctx context.Context) error
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

// CommandError is a failed service manager command.
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

// commandTimeout bounds each service manager command, so a hung systemctl or
// launchctl never stalls connect, set or uninstall.
const commandTimeout = 60 * time.Second

// runner runs one service manager command, given by absolute path, and
// returns its standard output; tests replace it.
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

// Executable is the real path of the running binary, every symlink resolved:
// the file the service definition runs and security.CheckServiceBinary
// checks. A package manager's link is not kept, because the check must judge
// the file that actually executes.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate the localport executable: %w", err)
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve the localport executable %s: %w", exe, err)
	}
	return filepath.Abs(real)
}

// AgentAccount is the system account the device service runs as.
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
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if !bytes.Contains(content, []byte(Marker)) {
		return true, fmt.Errorf("%w: %s; move it aside or remove it, then run the command again", ErrForeignUnit, path)
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
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
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
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
