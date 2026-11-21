//go:build cgo

package sessionhelper

// ioctlGetSession is TIOCGSID, _IOR('t', 99, int) in <sys/ioctl_compat.h>;
// golang.org/x/sys/unix does not define it for darwin.
const ioctlGetSession = 0x40047463
