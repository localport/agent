//go:build !windows

package securitytest

import (
	"os"
	"path/filepath"
	"testing"
)

func dirWithMode(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func ownerOnlyDir(t *testing.T) string { return dirWithMode(t, "private", 0o700) }

// sharedDir lets the group read only, which a writer check passes.
func sharedDir(t *testing.T) string { return dirWithMode(t, "shared", 0o750) }
