package security

import (
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

// EnsurePrivateDir creates dir and any missing parents under root, restricted
// to the current user.
//
// Only the components below root are checked for symlinks. Root itself is
// configuration and the operator chose it, whereas everything under it is
// created by us, so a link appearing there means somebody redirected a
// credential. Walking the whole absolute path instead would reject ordinary
// system layouts, where /var is a symlink on macOS and /home is on several BSDs.
func EnsurePrivateDir(root, dir string) error {
	if err := mkdirPrivate(dir); err != nil {
		return err
	}
	return refuseSymlinkBelow(root, dir)
}

func refuseSymlinkBelow(root, dir string) error {
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

	cur := absRoot
	if rel == "." {
		return nil
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", cur, err)
		}
		if isRedirect(info) {
			return fmt.Errorf("%s redirects elsewhere; credential paths must not be redirected", cur)
		}
	}
	return nil
}
