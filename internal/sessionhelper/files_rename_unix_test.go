//go:build linux || darwin

package sessionhelper

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// renameNoReplace refuses an existing target and leaves both names unchanged.
func TestRenameNoReplaceRefusesAnExistingTarget(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, data := range map[string]string{"from": "a", "to": "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := renameNoReplace(root, "from", "to"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("rename over an existing target = %v, want fs.ErrExist", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "to")); err != nil || string(b) != "b" {
		t.Fatalf("target %q, %v after the refused rename", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "from")); err != nil {
		t.Fatalf("source after the refused rename: %v", err)
	}
}

// renameNoReplace never replaces a target, whichever of a racing create and
// the rename lands first.
func TestRenameNoReplaceDoesNotReplaceARacingCreate(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for i := range 200 {
		if err := os.Mkdir(filepath.Join(dir, "from"), 0o755); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var renameErr error
		created := false
		wg.Go(func() { renameErr = renameNoReplace(root, "from", "to") })
		wg.Go(func() { created = os.Mkdir(filepath.Join(dir, "to"), 0o700) == nil })
		wg.Wait()
		info, statErr := os.Stat(filepath.Join(dir, "to"))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if created && renameErr == nil {
			t.Fatalf("round %d: a racing create was replaced (mode %v)", i, info.Mode())
		}
		if created && !errors.Is(renameErr, fs.ErrExist) {
			t.Fatalf("round %d: rename over a created target = %v", i, renameErr)
		}
		_ = os.RemoveAll(filepath.Join(dir, "from"))
		_ = os.RemoveAll(filepath.Join(dir, "to"))
	}
}

// A FIFO named as the target's parent is refused at once.
func TestRenameNoReplaceDoesNotBlockOnAFIFOParent(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- renameNoReplace(root, "d", "fifo/x") }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a rename under a FIFO succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the rename blocked on the FIFO")
	}
}

// A rename stays inside the root.
func TestRenameNoReplaceIsConfined(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "root")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := renameNoReplace(root, "d", "out/escaped"); err == nil {
		t.Fatal("a rename through a symlink out of the root succeeded")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped")); err == nil {
		t.Fatal("the directory left the root")
	}
}
