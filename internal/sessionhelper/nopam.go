//go:build cgo && !pam && linux

package sessionhelper

/*
#include <errno.h>
#include <shadow.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// pamAvailable reports that this build opens no PAM session: hosts without
// libpam get the account checks sshd applies without PAM instead.
const pamAvailable = false

// pamSession is empty without PAM.
type pamSession struct{}

func openPAM(string, string, string, uint32, *pamMessages) (*pamSession, error) {
	return &pamSession{}, nil
}
func (*pamSession) env() []string { return nil }
func (*pamSession) close()        {}

// restoreStartFileLimit has nothing to do without PAM: os/exec gives each
// child the limit the helper started with.
func restoreStartFileLimit() error { return nil }

// accountChecks applies sshd's checks for a host without PAM: /etc/nologin
// (checkNologin), and a shadow entry that is not locked and not expired
// (checkShadow). A host with no shadow entry for the account (no
// /etc/shadow, or NSS without shadow) passes that check, as sshd's does.
func accountChecks(a account) error {
	if err := checkNologin(a.UID, nologinPath); err != nil {
		return err
	}
	return shadowChecks(a.Name, time.Now())
}

func shadowChecks(name string, now time.Time) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	buf := make([]byte, 16<<10)
	var sp C.struct_spwd
	var result *C.struct_spwd
	rc := C.getspnam_r(cname, &sp, (*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &result)
	if rc == C.ENOENT || (rc == 0 && result == nil) {
		return nil
	}
	if rc != 0 {
		return fmt.Errorf("read the shadow entry of %q: %w", name, syscall.Errno(rc))
	}
	return checkShadow(C.GoString(sp.sp_pwdp), int64(sp.sp_expire), now)
}
