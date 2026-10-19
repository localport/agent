//go:build !windows

package security

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckRootOnly(t *testing.T) {
	names := map[uint32]string{50: "staff", 80: "admin", 20: "staff"}
	lookup := func(gid uint32) (string, error) {
		if n, ok := names[gid]; ok {
			return n, nil
		}
		return "", errors.New("unknown group")
	}
	dir := func(perm fs.FileMode) fs.FileMode { return fs.ModeDir | perm }
	for _, c := range []struct {
		name string
		e    binaryEntry
		goos string
		ok   bool
	}{
		{"root file 0755", binaryEntry{path: "/usr/local/bin/localport", mode: 0o755, leaf: true}, "linux", true},
		{"root dir 0755", binaryEntry{path: "/usr/local/bin", mode: dir(0o755)}, "darwin", true},
		{"user-owned file", binaryEntry{path: "/opt/homebrew/bin/localport", mode: 0o755, uid: 501, leaf: true}, "darwin", false},
		{"user-owned dir", binaryEntry{path: "/home/pi/.local/bin", mode: dir(0o755), uid: 1000}, "linux", false},
		{"other-writable dir", binaryEntry{path: "/tmp", mode: dir(0o1777)}, "linux", false},
		{"other-writable file", binaryEntry{path: "/x", mode: 0o757, leaf: true}, "linux", false},
		{"group write gid 0", binaryEntry{path: "/usr/local", mode: dir(0o775)}, "darwin", true},
		{"Debian staff", binaryEntry{path: "/usr/local", mode: dir(0o2775), gid: 50}, "linux", true},
		{"staff on macOS", binaryEntry{path: "/usr/local", mode: dir(0o775), gid: 20}, "darwin", false},
		{"macOS admin", binaryEntry{path: "/usr/local/bin", mode: dir(0o775), gid: 80}, "darwin", false},
		{"unknown group", binaryEntry{path: "/opt", mode: dir(0o775), gid: 7}, "linux", false},
		{"group bit unset, any gid", binaryEntry{path: "/opt", mode: dir(0o755), gid: 7}, "linux", true},
		{"leaf directory", binaryEntry{path: "/usr/local/bin", mode: dir(0o755), leaf: true}, "linux", false},
		{"ancestor symlink", binaryEntry{path: "/bin", mode: fs.ModeSymlink | 0o777}, "linux", false},
	} {
		err := checkRootOnly(c.e, c.goos, lookup)
		if c.ok && err != nil {
			t.Errorf("%s: %v, want accepted", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrUnsafeExecutable) {
			t.Errorf("%s: %v, want ErrUnsafeExecutable", c.name, err)
		}
	}
}

// A binary in a temp directory is refused for its non-root owner. Under root
// the temp binary is root-owned, so the test skips.
func TestCheckServiceBinaryRefusesATempBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "localport")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: the temp binary is root-owned, so this test cannot show the owner refusal")
	}
	if err := CheckServiceBinary(real); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("CheckServiceBinary(%s) = %v, want ErrUnsafeExecutable", real, err)
	}
	if err := CheckServiceBinary("bin/localport"); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("relative path = %v, want ErrUnsafeExecutable", err)
	}
}

// A system binary in a stock root-owned tree is accepted.
func TestCheckServiceBinaryAcceptsASystemBinary(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh: %v", err)
	}
	if err := CheckServiceBinary(sh); err != nil {
		t.Fatalf("CheckServiceBinary(%s) = %v, want accepted", sh, err)
	}
}
