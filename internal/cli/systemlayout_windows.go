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
// directory and run.lock with the system DACLs (config.EnsureSystemRunLock)
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
	dir := filepath.Dir(file.Path)
	if err := moveLegacySpool(ctx, dir, m, exe); err != nil {
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
// the service is stopped, then installs the service again.
func moveLegacySpool(ctx context.Context, dir string, m service.Manager, exe string) error {
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
	if err := moveSpool(from, filepath.Join(dir, "identity", "recordings")); err != nil {
		if installed {
			return fmt.Errorf("%w\n  %s is stopped; fix the cause, then run: %s", err, m.Name(), serviceInstallCommand)
		}
		return err
	}
	if installed {
		return m.Install(ctx, exe)
	}
	return nil
}

// removeAgentAccount is never reached on Windows, which has no agent account.
func removeAgentAccount(context.Context, string) error { return nil }
