//go:build !windows

package securitytest

import (
	"os"
	"testing"
)

// RequireOwnerOnly fails the test unless path carries no group or other
// permission bits.
func RequireOwnerOnly(t testing.TB, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("%s mode %#o grants group or other access", path, perm)
	}
}
