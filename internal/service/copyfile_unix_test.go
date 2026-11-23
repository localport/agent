//go:build darwin || linux

package service

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A bundle file swapped after the walk for a symlink or another file is not copied.
func TestCopyFileRefusesASwappedSource(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src, other := filepath.Join(dir, "src"), filepath.Join(dir, "other")
	for _, p := range []string{src, other} {
		if err := os.WriteFile(p, []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	walked, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, filepath.Join(dir, "same"), walked); err != nil {
		t.Fatalf("unchanged source: %v", err)
	}
	for name, swap := range map[string]func() error{
		"symlink": func() error { return os.Symlink(other, src) },
		"file":    func() error { return os.Link(other, src) },
	} {
		if err := os.Remove(src); err != nil {
			t.Fatal(err)
		}
		if err := swap(); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(dir, "copy-"+name)
		if err := copyFile(src, dst, walked); err == nil {
			t.Errorf("%s: copied a swapped source", name)
		}
		if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: staged %s: %v", name, dst, err)
		}
	}
}

// A bundle file swapped for a FIFO or a symlink to one, or reached through a
// parent directory swapped for a symlink, is refused without opening a FIFO.
func TestCopyFileRefusesASwappedFIFOOrLink(t *testing.T) {
	for name, swap := range map[string]func(t *testing.T, bundle, fifo string){
		"fifo": func(t *testing.T, bundle, _ string) {
			src := filepath.Join(bundle, "Contents", "src")
			if err := os.Remove(src); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(src, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"link": func(t *testing.T, bundle, fifo string) {
			src := filepath.Join(bundle, "Contents", "src")
			if err := os.Remove(src); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(fifo, src); err != nil {
				t.Fatal(err)
			}
		},
		"parent link": func(t *testing.T, bundle, fifo string) {
			contents, elsewhere := filepath.Join(bundle, "Contents"), filepath.Join(filepath.Dir(fifo), "elsewhere")
			if err := os.Mkdir(elsewhere, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(filepath.Join(elsewhere, "src"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(contents); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, contents); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			bundle, fifo := filepath.Join(dir, "bundle"), filepath.Join(dir, "fifo")
			src := filepath.Join(bundle, "Contents", "src")
			if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(src, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			walked, err := os.Lstat(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			swap(t, bundle, fifo)
			done := make(chan error, 1)
			go func() { done <- copyFile(src, filepath.Join(dir, "dst"), walked) }()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("copied a swapped source")
				}
				if name != "fifo" && !errors.Is(err, syscall.ELOOP) {
					t.Fatalf("%v, want ELOOP from the open", err)
				}
			case <-time.After(5 * time.Second):
				// Unblock the open so the goroutine ends.
				for _, p := range []string{fifo, src} {
					if w, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						w.Close()
					}
				}
				t.Fatal("copyFile opened a FIFO")
			}
		})
	}
}
