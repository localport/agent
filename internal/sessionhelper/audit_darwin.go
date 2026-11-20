//go:build cgo && darwin

package sessionhelper

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -lbsm
#include <bsm/audit.h>
#include <bsm/audit_session.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

// lp_new_audit_session gives this process a new remote login audit session,
// as Apple OpenSSH's bsm_audit_session_setup (audit-bsm.c) does: a new
// session id, the login's audit user id, the remote and authenticated flags
// (and the TTY flag for a PTY), the login's preselection mask, and the
// client's address as the terminal id. au_user_mask failing (no audit_control
// on the host) leaves the mask empty: nothing extra is preselected.
static int lp_new_audit_session(uid_t uid, const char *name, int tty, unsigned int type, const unsigned char *addr, unsigned int port) {
	auditinfo_addr_t info;
	au_mask_t mask;
	memset(&info, 0, sizeof(info));
	memset(&mask, 0, sizeof(mask));
	if (au_user_mask((char *)name, &mask) == 0) info.ai_mask = mask;
	info.ai_auid = uid;
	info.ai_asid = AU_ASSIGN_ASID;
	info.ai_flags = AU_SESSION_FLAG_IS_REMOTE | AU_SESSION_FLAG_HAS_AUTHENTICATED;
	if (tty) info.ai_flags |= AU_SESSION_FLAG_HAS_TTY;
	info.ai_termid.at_port = port;
	info.ai_termid.at_type = type;
	if (type != 0) memcpy(info.ai_termid.at_addr, addr, type);
	if (setaudit_addr(&info, sizeof(info)) != 0) return errno;
	return 0;
}
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/localport/agent/internal/launcher"
)

// newAuditSession gives the helper, and every process it starts, a new BSM
// audit session for the login uid as Apple's sshd does, so BSM audit and
// Endpoint Security attribute the session's activity to the login and mark
// it remote. clientAddr is the session client's `ip:port`; empty or invalid
// leaves the terminal id empty.
func newAuditSession(uid uint32, name string, tty bool, clientAddr string) error {
	var addr [16]byte
	typ, port := C.uint(0), C.uint(0)
	if ip, p, ok := launcher.SplitClientAddr(clientAddr); ok {
		parsed := net.ParseIP(ip)
		if v4 := parsed.To4(); v4 != nil {
			copy(addr[:], v4)
			typ = C.AU_IPv4
		} else {
			copy(addr[:], parsed.To16())
			typ = C.AU_IPv6
		}
		port = C.uint(p)
	}
	t := C.int(0)
	if tty {
		t = 1
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	if rc := C.lp_new_audit_session(C.uid_t(uid), cname, t, typ, (*C.uchar)(unsafe.Pointer(&addr[0])), port); rc != 0 {
		return fmt.Errorf("setaudit_addr: %w", syscall.Errno(rc))
	}
	return nil
}
