package security

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Owner-only files and directories for private key material.
//
// Two properties the plain os package does not provide:
//
//   - Validation runs on an open descriptor, never on a path. Checking a path
//     and then opening it leaves a window in which the file can be replaced.
//   - Symlinks are refused rather than followed, so a link planted in advance
//     cannot redirect a key to a location its owner can read.
//
// On Unix the mode bits carry the policy. On Windows the Go runtime synthesises
// them from the read-only attribute alone, so they say nothing about who can
// read the file; the DACL carries the policy there instead.

// Modes for everything the store creates. On Windows the DACL is
// authoritative and these are only passed to Go.
const (
	privateDirPerm  os.FileMode = 0o700
	privateFilePerm os.FileMode = 0o600
)

// ReadPrivateFile reads a file that must be reachable only by its owner.
func ReadPrivateFile(path string) ([]byte, error) {
	f, err := OpenPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// OpenPrivateFile opens a file for reading and refuses it if anything other
// than its owner can reach it. The caller closes the returned handle.
func OpenPrivateFile(path string) (*os.File, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	if err := verifyPrivate(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// WritePrivateFileAtomic writes data to a temporary sibling and renames it over
// path, so a concurrent reader sees either the old file or the new one and
// never a partial write.
func WritePrivateFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear %s: %w", tmp, err)
	}
	f, err := createPrivate(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	// Flushed before the rename, not after. A rename is ordered but the DATA is
	// not, so a power loss here can leave a present-but-empty key. Recovering
	// from that costs a fresh setup token, and the old one is single-use and
	// already spent.
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("flush %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	// Then the directory entry, so the rename itself survives a power loss.
	// Best-effort: Windows cannot fsync a directory handle, and some filesystems
	// refuse it. The file's own contents are already durable either way, so a
	// failure here costs the rename, not the key.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// ErrUntrustedPath is returned for a credential path that is a symlink or
// reparse point, is not a directory, or is owned by another user.
var ErrUntrustedPath = errors.New("untrusted credential path")

// EnsurePrivateDir creates dir and any missing parents under root, restricted
// to the current user.
//
// Each component from root down to dir is opened without following links and
// checked on the descriptor. It must be a directory owned by the effective
// user, and its mode is changed through that descriptor. Components above root
// are not walked, /var is a symlink on macOS and /home on some BSDs. Root is
// followed only with followRoot, set for LOCALPORT_HOME and $HOME.
func EnsurePrivateDir(root, dir string, followRoot bool) error {
	return walkPrivateDir(root, dir, followRoot, true)
}

func walkPrivateDir(root, dir string, followRoot, secure bool) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", root, err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	rel, err := filepath.Rel(absRoot, absDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%s is not inside %s", absDir, absRoot)
	}

	if secure {
		if err := os.MkdirAll(filepath.Dir(absRoot), privateDirPerm); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(absRoot), err)
		}
	}
	if err := inspectPrivateDir(absRoot, followRoot, secure); err != nil {
		if errors.Is(err, ErrUntrustedPath) {
			return fmt.Errorf("%w; change its owner to this account, or set LOCALPORT_HOME to a directory this account owns", err)
		}
		return err
	}
	if rel == "." {
		return nil
	}
	cur := absRoot
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		if err := inspectPrivateDir(cur, false, secure); err != nil {
			return err
		}
	}
	return nil
}

// OpenLockFile opens or creates path read-write without following a symlink or
// reparse point.
func OpenLockFile(path string) (*os.File, error) {
	return openLockNoFollow(path)
}
