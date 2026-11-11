package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/service"
)

// needsSystemLayout reports whether this process is an elevated
// Administrator acting on the system config, which prepareSystemLayout
// readies.
func needsSystemLayout(file config.LocalConfigFile) bool {
	return file.System && security.IsSystemWriter(0)
}

// prepareSystemLayout readies the machine-wide state for the device
// service, as an elevated Administrator, before the service runs: the device
// directory and run.lock with the system DACLs (config.EnsureSystemRunLock),
// the two crash directories (security.EnsureCrashDir: crash\device, which
// the device service may modify, and crash\launcher, which it cannot reach),
// and agent.yaml owned by Administrators and read-only to the service
// (security.AdoptSystemFile). An install from before this layout is
// converted in place: a <device dir>\recordings spool moves into the
// identity directory with the service (m, when installed) stopped, and the
// service is installed again for exe. The identity directory keeps its
// DACL, which already belongs to the service. It is idempotent.
func prepareSystemLayout(ctx context.Context, file config.LocalConfigFile, m service.Manager, exe string) error {
	if err := config.EnsureSystemRunLock(file); err != nil {
		return err
	}
	for _, name := range []string{service.WindowsName, service.LauncherName} {
		if dir, deviceService := service.CrashDir(name); dir != "" {
			if err := security.EnsureCrashDir(dir, deviceService); err != nil {
				return err
			}
		}
	}
	if err := moveLegacySpool(ctx, file, m, exe); err != nil {
		return err
	}
	if _, err := os.Lstat(file.Path); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect %s: %w", file.Path, err)
	}
	unlock, err := config.LockLocal(file)
	if err != nil {
		return err
	}
	defer unlock()
	return security.AdoptSystemFile(file.Path)
}

// moveLegacySpool moves <dir>\recordings into the identity directory while
// the service is stopped and run.lock is held, then installs the service
// again. Every failure after the stop names the reinstall remedy.
func moveLegacySpool(ctx context.Context, file config.LocalConfigFile, m service.Manager, exe string) error {
	dir := filepath.Dir(file.Path)
	from := filepath.Join(dir, "recordings")
	if _, err := os.Lstat(from); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect %s: %w", from, err)
	}
	installed := false
	if m != nil {
		var err error
		if installed, err = m.Installed(); err != nil {
			return err
		}
	}
	if installed {
		if err := m.Stop(ctx); err != nil {
			return fmt.Errorf("stop %s before moving %s: %w", m.Name(), from, err)
		}
	}
	stopped := func(err error) error {
		if !installed {
			return err
		}
		return fmt.Errorf("%w\n  %s is stopped; fix the cause, then run: %s", err, m.Name(), serviceInstallCommand)
	}
	// run.lock keeps another agent run from writing the old spool while it
	// moves; it is released before Install, whose service takes it.
	release, err := config.LockRunContext(ctx, file, serviceRunLockWait)
	if err != nil {
		return stopped(err)
	}
	err = moveSpool(from, filepath.Join(dir, "identity", "recordings"))
	if err = errors.Join(err, release()); err != nil {
		return stopped(err)
	}
	if installed {
		if err := m.Install(ctx, exe); err != nil {
			return stopped(err)
		}
	}
	return nil
}

// removeAgentAccount is never reached on Windows, which has no agent account.
func removeAgentAccount(context.Context, config.LocalConfigFile) error { return nil }
