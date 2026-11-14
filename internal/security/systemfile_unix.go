//go:build !windows

package security

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/localport/agent/internal/errcode"
)

const (
	systemDirPerm  os.FileMode = 0o750
	systemFilePerm os.FileMode = 0o640
	// SystemRunLockPerm is run.lock: root and the agent group lock it.
	SystemRunLockPerm os.FileMode = 0o660
	// SystemConfigLockPerm is agent.yaml.lock: only root writes the config.
	SystemConfigLockPerm os.FileMode = 0o600
)

// AgentGroupID returns the gid of AgentGroup, or ErrAgentGroupMissing.
func AgentGroupID() (int, error) {
	g, err := user.LookupGroup(AgentGroup)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return 0, ErrAgentGroupMissing
		}
		return 0, errcode.New(errcode.AccountNotChanged).With(err, "look up group "+AgentGroup)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, errcode.New(errcode.AccountNotChanged).With(nil, fmt.Sprintf("group %s has a non-numeric gid %q", AgentGroup, g.Gid))
	}
	return gid, nil
}

// IsSystemWriter reports whether euid owns the system files.
func IsSystemWriter(euid int) bool { return euid == systemOwner }

// CheckSystemDir refuses dir unless it is a directory, not a symlink, owned by
// root and writable by nobody else. It changes nothing.
func CheckSystemDir(dir string) error {
	f, err := openSystemDir(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if err := checkSystemOwner(info, dir); err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is writable by group or other (mode %#o, want 0750)", dir, perm))
	}
	return nil
}

// EnsureSystemDir creates dir when missing and, through its descriptor, sets
// it root:gid 0750. Root only. A directory owned by anyone but root is
// refused, not taken over: its owner could have placed links in it.
func EnsureSystemDir(dir string, gid int) error {
	if err := os.Mkdir(dir, systemDirPerm); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := openSystemDir(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if err := checkSystemOwner(info, dir); err != nil {
		return err
	}
	if err := f.Chown(systemOwner, gid); err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	if err := f.Chmod(systemDirPerm); err != nil {
		return fmt.Errorf("secure %s: %w", dir, err)
	}
	return nil
}

// ReadSystemFile reads a regular file owned by root that neither group nor
// other can write and other cannot read.
func ReadSystemFile(path string) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) || errors.Is(err, refusedLinkErrno) {
			return nil, ErrUntrustedPath.With(nil, fmt.Sprintf("%s is a symlink", path))
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	if err := checkSystemRegular(info, path); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o027 != 0 {
		return nil, ErrUntrustedPath.With(nil, fmt.Sprintf("%s has too-open permissions %#o (want 0640 or stricter)", path, perm))
	}
	return io.ReadAll(f)
}

// WriteSystemFileAtomic is WritePrivateFileAtomic for a system file: the
// temporary sibling is set root:gid 0640 through its descriptor before the
// rename.
func WriteSystemFileAtomic(path string, data []byte, gid int) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear %s: %w", tmp, err)
	}
	f, err := createPrivate(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	fail := func(step string, err error) error {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("%s %s: %w", step, tmp, err)
	}
	if err := f.Chown(systemOwner, gid); err != nil {
		return fail("secure", err)
	}
	if err := f.Chmod(systemFilePerm); err != nil {
		return fail("secure", err)
	}
	if _, err := f.Write(data); err != nil {
		return fail("write", err)
	}
	if err := f.Sync(); err != nil {
		return fail("flush", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	SyncDir(filepath.Dir(path))
	return nil
}

// OpenSystemLock opens or creates the lock file path read-write as root,
// without following a symlink, and sets it root:gid with perm through its
// descriptor (SystemRunLockPerm or SystemConfigLockPerm).
func OpenSystemLock(path string, gid int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err == nil {
		err = checkSystemRegular(info, path)
	}
	if err == nil {
		err = f.Chown(systemOwner, gid)
	}
	if err == nil {
		err = f.Chmod(perm)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("secure %s: %w", path, err)
	}
	return f, nil
}

// OpenSystemRunLock opens the existing run.lock read-write for a process other
// than root, without creating it or following a symlink, and refuses it unless
// it is a regular file owned by root.
func OpenSystemRunLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	info, err := f.Stat()
	if err == nil {
		err = checkSystemRegular(info, path)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func openSystemDir(dir string) (*os.File, error) {
	f, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EMLINK) || errors.Is(err, refusedLinkErrno) {
			return nil, ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a directory of its own; the device directory must not be redirected", dir))
		}
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	return f, nil
}

func checkSystemRegular(info os.FileInfo, path string) error {
	if info.Mode()&os.ModeType != 0 {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("%s is not a regular file", path))
	}
	return checkSystemOwner(info, path)
}

func checkSystemOwner(info os.FileInfo, path string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrUntrustedPath.With(nil, fmt.Sprintf("cannot read ownership of %s", path))
	}
	if int(st.Uid) != systemOwner {
		return ErrUntrustedPath.With(errForeignOwner, fmt.Sprintf("%s is owned by uid %d, not %d", path, st.Uid, systemOwner))
	}
	return nil
}
