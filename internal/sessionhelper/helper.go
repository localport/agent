//go:build cgo && (linux || darwin)

// Package sessionhelper is `localport-session helper`: one root process per
// session that the launcher starts with the session channel on fd 3 and its
// control socket on fd 4. It resolves the login through NSS, runs the PAM
// service `localport` (account, setcred, open_session; on a no-PAM build
// the account checks sshd applies without PAM), opens the PTY, writes utmp,
// starts the login's shell as its parent, relays the PTY over the channel's
// frames, and on the end closes the PAM session and clears utmp.
//
// The caller runs Run on the main goroutine with the OS thread locked:
// pam_loginuid and pam_selinux act on the calling thread, and the shell is
// forked from it.
package sessionhelper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

const (
	channelFD = 3
	controlFD = 4
)

// Run serves one session and returns the helper's exit status: 0 after a
// session ran, 1 when it did not start.
func Run(log func(string, ...any)) int {
	closeExtraFDs(controlFD + 1)
	channel := os.NewFile(channelFD, "session-channel")
	control := os.NewFile(controlFD, "launcher-control")
	if channel == nil || control == nil {
		log("sessionhelper: started without the channel and control descriptors")
		return 1
	}
	req, err := launcher.ReadHelperRequest(control)
	if err != nil {
		log("sessionhelper: read the request: %v", err)
		return 1
	}
	refuse := func(code string, err error) int {
		log("sessionhelper: %s for %q: %v", code, req.Login, err)
		_ = launcher.WriteHelperReply(control, launcher.HelperReply{Refused: code})
		return 1
	}
	if req.Kind != launcher.KindTerminal {
		return refuse(launcher.CodeUnsupportedKind, errors.New(req.Kind))
	}

	a, err := lookupAccount(req.Login)
	if err != nil {
		return refuse(launcher.CodeAccountUnavailable, err)
	}
	shell := a.Shell
	if req.AgentAccount {
		// The agent account's login shell is nologin.
		shell = "/bin/sh"
	} else if err := accountChecks(a); err != nil {
		return refuse(launcher.CodeAccountRefused, err)
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	if err := shellUsable(shell); err != nil {
		return refuse(launcher.CodeAccountRefused, err)
	}

	master, slave, err := openPTY(uint16(req.Cols), uint16(req.Rows))
	if err != nil {
		return refuse(launcher.CodeSpawnFailed, err)
	}
	var pam *pamSession
	if pamAvailable && !req.AgentAccount {
		pam, err = openPAM(a.Name, slave.Name())
		if err != nil {
			_ = master.Close()
			_ = slave.Close()
			if errors.Is(err, errPAMAccount) {
				return refuse(launcher.CodeAccountRefused, err)
			}
			return refuse(launcher.CodePAMFailed, err)
		}
	}
	var pamEnv []string
	if pam != nil {
		pamEnv = pam.env()
	}
	plan := spawnPlan{
		path: shell,
		args: []string{"-" + filepath.Base(shell)},
		env:  sessionEnv(a, shell, req.Term, loginDefsPath(a.UID), pamEnv),
		dir:  workDir(a.Home),
		cred: &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: a.Groups},
	}
	out := &frameWriter{w: channel}
	k, err := startTerminal(out, master, slave, plan, log)
	if err != nil {
		pam.close()
		_ = master.Close()
		_ = slave.Close()
		return refuse(launcher.CodeSpawnFailed, err)
	}
	ut := utmpLogin(slave.Name(), a.Name, k.cmd.Process.Pid)
	if err := launcher.WriteHelperReply(control, launcher.HelperReply{Started: true}); err != nil {
		log("sessionhelper: reply started: %v", err)
		k.finish()
	}
	_ = control.Close()

	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		fr := launcher.NewFrameReader(channel)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			if err := k.handle(f); err != nil {
				log("sessionhelper: input: %v", err)
				return
			}
		}
	}()
	select {
	case <-k.ended:
	case <-inputDone:
	}
	k.finish()
	k.Wait()
	ut.logout()
	pam.close()
	_ = channel.Close()
	return 0
}

// errPAMAccount is an account refusal: by the PAM account stack (expired,
// locked, password change required, denied by policy), or by the checks a
// no-PAM build and every build apply (checkShadow, shellUsable).
var errPAMAccount = errors.New("account refused")

// checkShadow refuses a locked password field and an account past its
// expiry day (days since 1970-01-01; -1 or 0 is none). Locked is a leading
// '!', as sshd's platform_locked_account on Linux (LOCKED_PASSWD_PREFIX);
// '*' alone only disables password logins, which these sessions never use.
func checkShadow(password string, expireDay int64, now time.Time) error {
	if strings.HasPrefix(password, "!") {
		return fmt.Errorf("%w: the account is locked", errPAMAccount)
	}
	if expireDay > 0 && now.Unix()/86400 >= expireDay {
		return fmt.Errorf("%w: the account expired", errPAMAccount)
	}
	return nil
}

// shellUsable refuses a login shell that is missing, not a regular file or
// has no execute bit, as sshd's allowed_user does.
func shellUsable(shell string) error {
	if !filepath.IsAbs(shell) {
		return fmt.Errorf("%w: login shell %q is not an absolute path", errPAMAccount, shell)
	}
	fi, err := os.Stat(shell)
	if err != nil {
		return fmt.Errorf("%w: login shell %s: %w", errPAMAccount, shell, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%w: login shell %s is not an executable file", errPAMAccount, shell)
	}
	return nil
}

// workDir is home when it is a directory, else /.
func workDir(home string) string {
	if home != "" {
		if fi, err := os.Stat(home); err == nil && fi.IsDir() {
			return home
		}
	}
	return "/"
}

// defaultPath is PATH when /etc/login.defs sets none.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// loginDefsPath is the PATH /etc/login.defs gives uid: ENV_SUPATH for root,
// ENV_PATH otherwise, each "PATH=..." or a bare value; defaultPath when it
// sets none.
func loginDefsPath(uid uint32) string {
	raw, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return defaultPath
	}
	return parseLoginDefsPath(string(raw), uid)
}

func parseLoginDefsPath(defs string, uid uint32) string {
	key := "ENV_PATH"
	if uid == 0 {
		key = "ENV_SUPATH"
	}
	for _, line := range strings.Split(defs, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != key {
			continue
		}
		if v := strings.TrimPrefix(fields[1], "PATH="); v != "" {
			return v
		}
	}
	return defaultPath
}

// sessionEnv is the shell's environment: the login's identity, TERM and
// PATH, then every variable PAM set, which overrides those of the same name.
// Nothing comes from the launcher's or the agent's environment.
func sessionEnv(a account, shell, term, path string, pamEnv []string) []string {
	env := map[string]string{
		"HOME": a.Home, "USER": a.Name, "LOGNAME": a.Name, "SHELL": shell,
		"TERM": term, "PATH": path,
	}
	order := []string{"HOME", "USER", "LOGNAME", "SHELL", "TERM", "PATH"}
	for _, kv := range pamEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if _, seen := env[k]; !seen {
			order = append(order, k)
		}
		env[k] = v
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+env[k])
	}
	return out
}

// closeExtraFDs makes every descriptor from first up close-on-exec, so the
// shell inherits only its PTY.
func closeExtraFDs(first int) {
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err == nil && fd >= first {
			unix.CloseOnExec(fd)
		}
	}
}
