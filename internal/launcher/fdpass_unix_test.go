//go:build linux || darwin

package launcher

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// dupFDs returns n fresh descriptors, closed at cleanup if still open.
func dupFDs(t *testing.T, n int) []int {
	t.Helper()
	var fds []int
	for range n {
		fd, err := unix.Dup(0)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, fd)
	}
	t.Cleanup(func() {
		for _, fd := range fds {
			if fdOpen(fd) {
				_ = unix.Close(fd)
			}
		}
	})
	return fds
}

func fdOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err != unix.EBADF
}

// A malformed control message closes every descriptor it carried.
func TestParseRightsClosesOnMalformedMessage(t *testing.T) {
	t.Run("bad header after rights", func(t *testing.T) {
		fds := dupFDs(t, 2)
		bad := make([]byte, unix.CmsgSpace(0))
		(*unix.Cmsghdr)(unsafe.Pointer(&bad[0])).SetLen(1 << 20)
		if _, err := parseRights(append(unix.UnixRights(fds...), bad...)); err == nil {
			t.Fatal("a header longer than the buffer parsed")
		}
		for _, fd := range fds {
			if fdOpen(fd) {
				t.Fatalf("descriptor %d left open", fd)
			}
		}
	})
	t.Run("partial descriptor", func(t *testing.T) {
		fds := dupFDs(t, 3)
		oob := unix.UnixRights(fds...)
		(*unix.Cmsghdr)(unsafe.Pointer(&oob[0])).SetLen(unix.CmsgLen(9))
		if _, err := parseRights(oob); err == nil {
			t.Fatal("a partial descriptor parsed")
		}
		// The message carries two whole descriptors; the cut third stays the
		// test's.
		for _, fd := range fds[:2] {
			if fdOpen(fd) {
				t.Fatalf("descriptor %d left open", fd)
			}
		}
	})
}
