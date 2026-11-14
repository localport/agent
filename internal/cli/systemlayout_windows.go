package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

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
// (security.AdoptSystemFile). The identity directory keeps its DACL, which
// already belongs to the service. It is idempotent.
func prepareSystemLayout(_ context.Context, file config.LocalConfigFile) error {
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

// removeAgentDirs is never reached on Windows, which has no agent account.
func removeAgentDirs(config.LocalConfigFile, string) error { return nil }
