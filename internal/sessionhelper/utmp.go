//go:build cgo && (linux || darwin)

package sessionhelper

/*
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <utmpx.h>

// lp_utmp writes a login (user non-NULL) or logout record for line and pid
// to utmp and wtmp. musl's utmpx functions are no-ops, so a musl host keeps
// no records. macOS pututxline writes both databases itself.
static void lp_utmp(const char *line, const char *id, const char *user, int pid) {
	struct utmpx ut;
	struct timeval tv;
	memset(&ut, 0, sizeof(ut));
	ut.ut_type = user != NULL ? USER_PROCESS : DEAD_PROCESS;
	ut.ut_pid = pid;
	strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	strncpy(ut.ut_id, id, sizeof(ut.ut_id));
	if (user != NULL) {
		strncpy(ut.ut_user, user, sizeof(ut.ut_user));
		strncpy(ut.ut_host, "localport", sizeof(ut.ut_host));
	}
	gettimeofday(&tv, NULL);
	ut.ut_tv.tv_sec = tv.tv_sec;
	ut.ut_tv.tv_usec = tv.tv_usec;
	setutxent();
	pututxline(&ut);
	endutxent();
#if defined(__GLIBC__)
	updwtmpx("/var/log/wtmp", &ut);
#endif
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

// utmpEntry is one session's utmp record, cleared by logout.
type utmpEntry struct {
	line, id string
	pid      int
}

// utmpLogin writes the login record of user on tty (a /dev path) for pid.
func utmpLogin(tty, user string, pid int) *utmpEntry {
	line := strings.TrimPrefix(tty, "/dev/")
	id := line
	if len(id) > 4 {
		id = id[len(id)-4:]
	}
	e := &utmpEntry{line: line, id: id, pid: pid}
	cl, ci, cu := C.CString(e.line), C.CString(e.id), C.CString(user)
	defer C.free(unsafe.Pointer(cl))
	defer C.free(unsafe.Pointer(ci))
	defer C.free(unsafe.Pointer(cu))
	C.lp_utmp(cl, ci, cu, C.int(pid))
	return e
}

// logout clears the record.
func (e *utmpEntry) logout() {
	if e == nil {
		return
	}
	cl, ci := C.CString(e.line), C.CString(e.id)
	defer C.free(unsafe.Pointer(cl))
	defer C.free(unsafe.Pointer(ci))
	C.lp_utmp(cl, ci, nil, C.int(e.pid))
}
