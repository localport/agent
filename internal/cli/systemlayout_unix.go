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
	if err := moveSpool(filepath.Join(dir, "recordings"), filepath.Join(idDir, "recordings")); err != nil {
		return err
	}
	if err := chownTree(idDir, acct.UID, acct.GID); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  handed %s to the account %s\n", idDir, service.AgentAccount)
	if installed {
		return m.Install(ctx, exe)
	}
	return nil
}

// moveSpool moves the recording spool a root-run agent kept in the device
// directory into the identity directory, unless one is already there.
func moveSpool(from, to string) error {
	fi, err := os.Lstat(from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", from, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory; move it aside, then run the command again", from)
	}
	if _, err := os.Lstat(to); err == nil {
		fmt.Fprintf(os.Stderr, "  kept %s; %s already exists\n", from, to)
		return nil
	}
	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("move %s to %s: %w", from, to, err)
	}
	return nil
}

// chownTree chowns path and everything below it to uid:gid. Each directory
// is opened relative to its parent's descriptor with O_NOFOLLOW and each
// entry is inspected with AT_SYMLINK_NOFOLLOW; a symlink or anything but a
// directory or regular file stops the walk, as the agent never writes one.
func chownTree(path string, uid, gid int) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	return chownDir(fd, path, uid, gid)
}

// chownDir chowns the directory fd (named path in errors) and its entries,
// and closes fd.
func chownDir(fd int, path string, uid, gid int) error {
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
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
			if err := unix.Fchownat(fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("chown %s: %w", child, err)
			}
		case syscall.S_IFDIR:
			sub, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", child, err)
			}
			if err := chownDir(sub, child, uid, gid); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s is not a regular file or directory; move it aside, then run the command again", child)
		}
	}
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
