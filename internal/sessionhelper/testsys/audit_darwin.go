//go:build cgo && darwin

package testsys

/*
#include <bsm/audit.h>
#include <bsm/audit_session.h>
#include <errno.h>

static int lp_getaudit(unsigned int *auid, unsigned long long *flags) {
	auditinfo_addr_t a;
	if (getaudit_addr(&a, sizeof(a)) != 0) return errno;
	*auid = a.ai_auid;
	*flags = a.ai_flags;
	return 0;
}
*/
import "C"

import "syscall"

// Audit session flags (bsm/audit_session.h).
const (
	AuditHasTTY           = uint64(C.AU_SESSION_FLAG_HAS_TTY)
	AuditIsRemote         = uint64(C.AU_SESSION_FLAG_IS_REMOTE)
	AuditHasAuthenticated = uint64(C.AU_SESSION_FLAG_HAS_AUTHENTICATED)
)

// Audit returns this process's audit user id and session flags.
func Audit() (auid uint32, flags uint64, err error) {
	var a C.uint
	var f C.ulonglong
	if rc := C.lp_getaudit(&a, &f); rc != 0 {
		return 0, 0, syscall.Errno(rc)
	}
	return uint32(a), uint64(f), nil
}
