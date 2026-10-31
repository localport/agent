//go:build cgo && (linux || darwin)

package sessionhelper

/*
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
typedef int lp_gid_t;
#else
typedef gid_t lp_gid_t;
#endif

static int lp_getgrouplist(const char *name, gid_t base, lp_gid_t *groups, int *n) {
	return getgrouplist(name, (lp_gid_t)base, groups, n);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// account is a login as NSS resolves it.
type account struct {
	Name   string
	UID    uint32
	GID    uint32
	Home   string
	Shell  string
	Groups []uint32
}

// errNoAccount means NSS has no account under the name.
var errNoAccount = errors.New("no such account")

// maxGroups bounds the supplementary groups read for one account.
const maxGroups = 65536

// lookupAccount resolves name through NSS (getpwnam_r, getgrouplist), so
// LDAP, SSSD and systemd-homed accounts resolve as the host's login does.
func lookupAccount(name string) (account, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	size := C.sysconf(C._SC_GETPW_R_SIZE_MAX)
	if size < 1024 {
		size = 16 << 10
	}
	for {
		buf := C.malloc(C.size_t(size))
		var pw C.struct_passwd
		var result *C.struct_passwd
		rc := C.getpwnam_r(cname, &pw, (*C.char)(buf), C.size_t(size), &result)
		if rc == C.ERANGE && size < 1<<20 {
			C.free(buf)
			size *= 2
			continue
		}
		if rc != 0 {
			C.free(buf)
			return account{}, fmt.Errorf("getpwnam_r %q: %w", name, syscall.Errno(rc))
		}
		if result == nil {
			C.free(buf)
			return account{}, fmt.Errorf("%q: %w", name, errNoAccount)
		}
		a := account{
			Name:  C.GoString(pw.pw_name),
			UID:   uint32(pw.pw_uid),
			GID:   uint32(pw.pw_gid),
			Home:  C.GoString(pw.pw_dir),
			Shell: C.GoString(pw.pw_shell),
		}
		C.free(buf)
		groups, err := groupList(cname, a.GID)
		if err != nil {
			return account{}, fmt.Errorf("groups of %q: %w", name, err)
		}
		a.Groups = groups
		return a, nil
	}
}

// groupList returns the account's groups, its primary group included.
func groupList(cname *C.char, gid uint32) ([]uint32, error) {
	n := C.int(64)
	for n <= maxGroups {
		groups := make([]C.lp_gid_t, n)
		got := n
		if C.lp_getgrouplist(cname, C.gid_t(gid), &groups[0], &got) >= 0 {
			out := make([]uint32, got)
			for i := range out {
				out[i] = uint32(groups[i])
			}
			return out, nil
		}
		// glibc and musl report the needed size in got; macOS does not.
		if got > n {
			n = got
		} else {
			n *= 2
		}
	}
	return nil, errors.New("more than 65536 groups")
}
