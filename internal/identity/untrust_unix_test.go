//go:build !windows

package identity

import (
	"os"
	"testing"
)

// untrustDir gives dir a group write bit, which the private-directory check
// refuses, and returns the function that makes it private again.
func untrustDir(t *testing.T, dir string) (restore func()) {
	t.Helper()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}
