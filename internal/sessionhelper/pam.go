//go:build cgo && ((pam && linux) || darwin)

package sessionhelper

/*
#cgo LDFLAGS: -lpam
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <grp.h>
#include <unistd.h>

// initgroups takes an int on macOS and a gid_t on Linux.
static int lp_initgroups(const char *user, unsigned int gid) { return initgroups(user, gid); }

// lp_conv answers no prompt: the session's identity was authenticated
// upstream, so a module that asks for input fails the step (PAM_CONV_ERR).
// Informational and error messages get empty replies.
static int lp_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data) {
	(void)data;
	if (n <= 0 || n > PAM_MAX_NUM_MSG) return PAM_CONV_ERR;
	struct pam_response *r = calloc((size_t)n, sizeof(*r));
	if (r == NULL) return PAM_BUF_ERR;
	for (int i = 0; i < n; i++) {
		int style = msg[i]->msg_style;
		if (style != PAM_TEXT_INFO && style != PAM_ERROR_MSG) {
			free(r);
			return PAM_CONV_ERR;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

static struct pam_conv lp_conversation = { lp_conv, NULL };

static int lp_start(const char *service, const char *user, pam_handle_t **h) {
	return pam_start(service, user, &lp_conversation, h);
}

static int lp_set_item(pam_handle_t *h, int item, const char *v) {
	return pam_set_item(h, item, v);
}

static char *lp_env_at(char **env, int i) { return env[i]; }
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// pamAvailable reports that this build opens a PAM session.
const pamAvailable = true

// pamService is the PAM service the helper runs, /etc/pam.d/localport.
const pamService = "localport"

// pamSession is one PAM transaction. Its methods run on the helper's locked
// OS thread: pam_loginuid writes /proc/self/loginuid and pam_selinux sets
// the exec context of the calling thread.
type pamSession struct {
	h      *C.pam_handle_t
	cred   bool
	opened bool
	last   C.int
}

// openPAM runs the account stack, establishes credentials and opens the
// session for login on tty (a device path such as /dev/pts/3). It sets this
// process's supplementary groups to the login's before pam_setcred, so groups
// a PAM module adds survive to the child, which keeps them (NoSetGroups).
func openPAM(login, tty string, gid uint32) (*pamSession, error) {
	cService, cUser := C.CString(pamService), C.CString(login)
	defer C.free(unsafe.Pointer(cService))
	defer C.free(unsafe.Pointer(cUser))
	p := &pamSession{}
	if rc := C.lp_start(cService, cUser, &p.h); rc != C.PAM_SUCCESS {
		return nil, fmt.Errorf("pam_start: %d", int(rc))
	}
	if err := p.setItem(C.PAM_TTY, tty); err != nil {
		p.end()
		return nil, err
	}
	if err := p.setItem(C.PAM_RUSER, login); err != nil {
		p.end()
		return nil, err
	}
	switch rc := C.pam_acct_mgmt(p.h, 0); rc {
	case C.PAM_SUCCESS:
	case C.PAM_NEW_AUTHTOK_REQD, C.PAM_ACCT_EXPIRED, C.PAM_AUTH_ERR, C.PAM_PERM_DENIED, C.PAM_USER_UNKNOWN:
		p.last = rc
		p.end()
		return nil, fmt.Errorf("%w: %s", errPAMAccount, p.strerror(rc))
	default:
		p.last = rc
		p.end()
		return nil, fmt.Errorf("pam_acct_mgmt: %s", p.strerror(rc))
	}
	if rc, errno := C.lp_initgroups(cUser, C.uint(gid)); rc != 0 {
		p.end()
		return nil, fmt.Errorf("initgroups: %w", errno)
	}
	if rc := C.pam_setcred(p.h, C.PAM_ESTABLISH_CRED); rc != C.PAM_SUCCESS {
		p.last = rc
		p.end()
		return nil, fmt.Errorf("pam_setcred: %s", p.strerror(rc))
	}
	p.cred = true
	if rc := C.pam_open_session(p.h, 0); rc != C.PAM_SUCCESS {
		p.last = rc
		p.end()
		return nil, fmt.Errorf("pam_open_session: %s", p.strerror(rc))
	}
	p.opened = true
	return p, nil
}

func (p *pamSession) setItem(item C.int, v string) error {
	cv := C.CString(v)
	defer C.free(unsafe.Pointer(cv))
	if rc := C.lp_set_item(p.h, item, cv); rc != C.PAM_SUCCESS {
		return fmt.Errorf("pam_set_item %d: %s", int(item), p.strerror(rc))
	}
	return nil
}

// env returns the environment the PAM modules set (pam_env, pam_systemd's
// XDG_* and others), as KEY=VALUE.
func (p *pamSession) env() []string {
	list := C.pam_getenvlist(p.h)
	if list == nil {
		return nil
	}
	var out []string
	for i := C.int(0); ; i++ {
		e := C.lp_env_at(list, i)
		if e == nil {
			break
		}
		out = append(out, C.GoString(e))
		C.free(unsafe.Pointer(e))
	}
	C.free(unsafe.Pointer(list))
	return out
}

// close closes the session, deletes the credentials and ends the
// transaction; safe after a partial open.
func (p *pamSession) close() {
	if p == nil || p.h == nil {
		return
	}
	if p.opened {
		p.last = C.pam_close_session(p.h, 0)
		p.opened = false
	}
	p.end()
}

func (p *pamSession) end() {
	if p.h == nil {
		return
	}
	if p.cred {
		_ = C.pam_setcred(p.h, C.PAM_DELETE_CRED)
		p.cred = false
	}
	C.pam_end(p.h, p.last)
	p.h = nil
}

func (p *pamSession) strerror(rc C.int) string {
	return C.GoString(C.pam_strerror(p.h, rc))
}

// accountChecks is not used with PAM: the account stack decides.
func accountChecks(account) error { return nil }
