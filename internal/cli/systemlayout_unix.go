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
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/service"
)

// needsSystemLayout reports whether this process is root acting on the
// system config, which prepareSystemLayout readies.
func needsSystemLayout(file config.LocalConfigFile) bool { return needsAgentChild(file) }

// prepareSystemLayout readies the machine-wide state for the agent account,
// as root, before the agent service runs or a child touches the store: the
// account (service.EnsureAccount), the device directory root:localport 0750
// with run.lock root:localport 0660 (config.EnsureSystemRunLock), the
// identity directory owned by the account with mode 0700, and agent.yaml
// root:localport 0640. An identity tree root owns, left by an agent that ran
// as root, is converted in place: the agent service (m, when installed) is
// stopped, the old <device dir>/recordings spool moves into the identity
// directory, the tree is chowned through directory descriptors without
// following any link, and the service is installed again for exe so its
// devices keep running as the account. It is idempotent, and a converted
// tree's contents are never touched.
func prepareSystemLayout(ctx context.Context, file config.LocalConfigFile, m service.Manager, exe string) error {
	acct, err := service.EnsureAccount(ctx)
	if err != nil {
		return err
	}
	if err := config.EnsureSystemRunLock(file); err != nil {
		return err
	}
	dir := filepath.Dir(file.Path)
	idDir := filepath.Join(dir, "identity")
	convert, err := ensureIdentityDir(idDir, acct)
	if err != nil {
		return err
	}
	if convert {
		if err := convertIdentityTree(ctx, dir, idDir, acct, m, exe); err != nil {
			return err
		}
	}
	return rewriteSystemConfig(file)
}

// ensureIdentityDir creates the identity directory owned by acct, mode
// 0700, or secures an existing one acct owns. It reports true for an
// existing directory root owns, which needs conversion, and refuses any
// other owner or a link.
func ensureIdentityDir(path string, acct service.Account) (convert bool, err error) {
	created := true
	if err := os.Mkdir(path, 0o700); errors.Is(err, fs.ErrExist) {
		created = false
	} else if err != nil {
		return false, fmt.Errorf("create %s: %w", path, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return false, fmt.Errorf("inspect %s: %w", path, err)
	}
	switch {
	case int(st.Uid) == acct.UID:
	case st.Uid == 0 && !created:
		return true, nil
	case st.Uid == 0:
		if err := unix.Fchown(fd, acct.UID, acct.GID); err != nil {
			return false, fmt.Errorf("chown %s: %w", path, err)
		}
	default:
		return false, fmt.Errorf("%s is owned by uid %d, neither root nor the account %s; move it aside, then run the command again", path, st.Uid, service.AgentAccount)
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return false, fmt.Errorf("secure %s: %w", path, err)
	}
	return false, nil
}

// convertIdentityTree hands a root-owned identity tree to acct, with the
// agent service stopped meanwhile so nothing writes into it.
func convertIdentityTree(ctx context.Context, dir, idDir string, acct service.Account, m service.Manager, exe string) error {
	installed := false
	if m != nil {
		var err error
		if installed, err = m.Installed(); err != nil {
			return err
		}
	}
	if installed {
		if err := m.Stop(ctx); err != nil {
			return fmt.Errorf("stop %s before handing %s to the account %s: %w", m.Name(), idDir, service.AgentAccount, err)
		}
	}
	stopped := func(err error) error {
		if !installed {
			return err
		}
		return fmt.Errorf("%w\n  %s is stopped; fix the cause, then run: %s", err, m.Name(), serviceInstallCommand)
	}
	if err := moveSpool(filepath.Join(dir, "recordings"), filepath.Join(idDir, "recordings")); err != nil {
		return stopped(err)
	}
	if err := chownTree(idDir, acct.UID, acct.GID); err != nil {
		return stopped(err)
	}
	fmt.Fprintf(os.Stderr, "  handed %s to the account %s\n", idDir, service.AgentAccount)
	if installed {
		return m.Install(ctx, exe)
	}
	return nil
}

// chownTree chowns path and everything below it to uid:gid. Each directory
// is opened relative to its parent's descriptor with O_NOFOLLOW and each
// entry is inspected with AT_SYMLINK_NOFOLLOW. A first pass changes nothing
// and refuses a symlink or anything but a directory or regular file, as the
// agent never writes one. The second pass chowns each directory after its
// entries, so a walk that stops partway leaves path owned by root and the
// next run converts again.
func chownTree(path string, uid, gid int) error {
	for _, apply := range []bool{false, true} {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		if err := walkTree(fd, path, uid, gid, apply); err != nil {
			return err
		}
	}
	return nil
}

// walkTree inspects (and with apply chowns) the directory fd, named path in
// errors, and its entries; it closes fd.
func walkTree(fd int, path string, uid, gid int, apply bool) error {
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, name := range names {
		child := filepath.Join(path, name)
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("inspect %s: %w", child, err)
		}
		switch st.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if !apply {
				continue
			}
			if err := unix.Fchownat(fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("chown %s: %w", child, err)
			}
		case syscall.S_IFDIR:
			sub, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", child, err)
			}
			if err := walkTree(sub, child, uid, gid, apply); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is not a regular file or directory; move it aside, then run the command again", child)
		}
	}
	if !apply {
		return nil
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// removeAgentAccount runs after `service uninstall --purge` emptied the
// store: when the identity directory holds nothing more it removes it, the
// agent's log directory and the account. While the directory still holds
// credentials (machine credentials from setup) the account keeps them, so a
// reinstall finds them under the same uid.
func removeAgentAccount(ctx context.Context, dir string) error {
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
	if err := service.RemoveAccount(ctx); errors.Is(err, service.ErrNoAccountTool) {
		fmt.Fprintf(os.Stderr, "  kept the account %s: this host has no userdel or deluser; the package that created it removes it\n", service.AgentAccount)
		return nil
	} else if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  removed the account %s\n", service.AgentAccount)
	return nil
}

// rewriteSystemConfig rewrites an existing agent.yaml under its lock, so
// one written before the agent account existed becomes root:localport 0640.
func rewriteSystemConfig(file config.LocalConfigFile) error {
	if _, err := os.Lstat(file.Path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	unlock, err := config.LockLocal(file)
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := config.LoadLocal(file)
	if err != nil {
		return err
	}
	return config.WriteLocal(file, cfg, identity.Ref{})
}
