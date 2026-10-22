//go:build linux || darwin

package recording

import (
	"errors"
	"io/fs"
	"syscall"
	"testing"
)

// A segment write that finds the filesystem or the quota full is ErrDiskLow,
// so the recording completes disk_low; any other write error is not.
func TestSpoolFullDiskWriteIsDiskLow(t *testing.T) {
	s, _ := openTestSpool(t, spoolDir(t))
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Fatal(err)
	}
	used := s.Used()
	for _, c := range []struct {
		err     error
		diskLow bool
	}{
		{&fs.PathError{Op: "write", Path: "0.seg", Err: syscall.ENOSPC}, true},
		{&fs.PathError{Op: "write", Path: "0.seg", Err: syscall.EDQUOT}, true},
		{&fs.PathError{Op: "write", Path: "0.seg", Err: syscall.EIO}, false},
	} {
		s.writeFile = func(string, []byte) error { return c.err }
		err := s.WriteSegment(spoolID1, Segment{Index: 0, Object: []byte("x")})
		if err == nil || errors.Is(err, ErrDiskLow) != c.diskLow || !errors.Is(err, c.err) {
			t.Fatalf("WriteSegment failing with %v = %v, want ErrDiskLow %v", c.err, err, c.diskLow)
		}
		if s.Used() != used {
			t.Fatalf("a failed write left the count at %d, want %d", s.Used(), used)
		}
	}
}
