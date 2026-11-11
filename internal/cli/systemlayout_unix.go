//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/service"
)

// needsSystemLayout reports whether this process is root acting on the
// system config, which prepareSystemLayout readies.
func needsSystemLayout(file config.LocalConfigFile) bool { return needsAgentChild(file) }

// prepareSystemLayout readies the machine-wide state for the agent account,
// as root, before the agent service runs or a child touches the store: the
// account (service.EnsureAccount), the device directory root:localport 0750
// with run.lock root:localport 0660 (config.EnsureSystemRunLock) and the
// identity directory owned by the account with mode 0700. agent.yaml gets
// root:localport 0640 from config.WriteLocal. It is idempotent.
func prepareSystemLayout(ctx context.Context, file config.LocalConfigFile) error {
	acct, err := service.EnsureAccount(ctx)
	if err != nil {
		return err
	}
	if err := config.EnsureSystemRunLock(file); err != nil {
		return err
	}
	return ensureIdentityDir(filepath.Join(filepath.Dir(file.Path), "identity"), acct)
}

// ensureIdentityDir creates the identity directory owned by acct, mode
// 0700, or secures an existing one acct owns. It refuses any other owner,
// root's included, and a link.
func ensureIdentityDir(path string, acct service.Account) error {
	created := true
	if err := os.Mkdir(path, 0o700); errors.Is(err, fs.ErrExist) {
		created = false
	} else if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	switch {
	case int(st.Uid) == acct.UID:
	case st.Uid == 0 && created:
		if err := unix.Fchown(fd, acct.UID, acct.GID); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	default:
		return fmt.Errorf("%s is owned by uid %d, not the account %s; move it aside, then run the command again", path, st.Uid, service.AgentAccount)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return fmt.Errorf("secure %s: %w", path, err)
	}
	return nil
}

// removeAgentAccount runs after `service uninstall --purge` emptied the
// store: when the identity directory holds nothing more it removes it, the
// agent's log directory and the account. While the directory still holds
// credentials (machine credentials from setup) the account keeps them, so a
// reinstall finds them under the same uid. The device directory and the lock
// files that stay carry the account's group; they move to group root before
// the group goes, so a group that later reuses the gid gains nothing.
func removeAgentAccount(ctx context.Context, file config.LocalConfigFile) error {
	dir := filepath.Dir(file.Path)
	idDir := filepath.Join(dir, "identity")
	switch err := os.Remove(idDir); {
	case err == nil, errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EEXIST):
		fmt.Fprintf(os.Stderr, "  kept the account %s: it owns the credentials left in %s\n", service.AgentAccount, idDir)
		return nil
	default:
		return fmt.Errorf("remove %s: %w", idDir, err)
	}
	// Its parent, /var/log, is writable by root only; RemoveAll unlinks a
	// link instead of following it.
	if err := os.RemoveAll(service.AgentLogDir); err != nil {
		return fmt.Errorf("remove %s: %w", service.AgentLogDir, err)
	}
	for _, path := range []string{dir, file.LockPath(), file.RunLockPath()} {
		if err := os.Lchown(path, -1, 0); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("give %s to group root before removing the account %s: %w", path, service.AgentAccount, err)
		}
	}
	if err := removeAccount(ctx); errors.Is(err, service.ErrNoAccountTool) {
		fmt.Fprintf(os.Stderr, "  kept the account %s: this host has no userdel or deluser; the package that created it removes it\n", service.AgentAccount)
		return nil
	} else if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  removed the account %s\n", service.AgentAccount)
	return nil
}

// removeAccount deletes the agent account; tests replace it.
var removeAccount = service.RemoveAccount
