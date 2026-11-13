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
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/launcher"
)

const (
	channelFD = 3
	controlFD = 4
)

// Run serves one session and returns the helper's exit status: 0 after a
// session ran, 1 when it did not start.
func Run(log func(string, ...any)) int {
	// The helper keeps using 3 and 4; no child may inherit either. startChild
	// marks every descriptor; these two are marked here as well so a host
	// where it cannot list descriptors still keeps them from the children.
	unix.CloseOnExec(channelFD)
	unix.CloseOnExec(controlFD)
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
	// msgs is what PAM modules say; both the refusal and the started reply
	// carry it to the client.
	msgs := &pamMessages{}
	refuse := func(code string, err error) int {
		log("sessionhelper: %s for %q: %v", code, req.Login, err)
		_ = launcher.WriteHelperReply(control, launcher.HelperReply{Refused: code, Messages: msgs.messages()})
		return 1
	}
	if req.Kind != launcher.KindTerminal && req.Kind != launcher.KindExec && req.Kind != launcher.KindSFTP && req.Kind != launcher.KindForward {
		return refuse(launcher.CodeUnsupportedKind, errors.New(req.Kind))
	}
	// An exec session without a size, and a file session, run on pipes;
	// every other session on a PTY.
	usePTY := req.Kind == launcher.KindTerminal || (req.Kind == launcher.KindExec && req.Cols > 0)

	a, err := lookupAccount(req.Login)
	if err != nil {
		return refuse(launcher.CodeAccountUnavailable, err)
	}
	shell := a.Shell
	if req.AgentAccount {
		// The agent account's login shell is nologin. No PAM runs for it, so
		// /etc/nologin is checked here on every build.
		shell = "/bin/sh"
		err = checkNologin(a.UID, nologinPath)
	} else {
		err = accountChecks(a)
	}
	if err != nil {
		noteNologin(msgs, err, nologinPath)
		return refuse(launcher.CodeAccountRefused, err)
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	if err := shellUsable(shell); err != nil {
		return refuse(launcher.CodeAccountRefused, err)
	}

	var master, slave *os.File
	pamTTY := "ssh" // PAM_TTY of a session without a terminal, as sshd sets it
	if usePTY {
		if master, slave, err = openPTY(uint16(req.Cols), uint16(req.Rows)); err != nil {
			return refuse(launcher.CodeSpawnFailed, err)
		}
		if err := setPTYOwner(slave, a.UID, a.GID); err != nil {
			_ = master.Close()
			_ = slave.Close()
			return refuse(launcher.CodeSpawnFailed, err)
		}
		pamTTY = slave.Name()
	}
	closePTY := func() {
		if usePTY {
			_ = master.Close()
			_ = slave.Close()
		}
	}
	var pam *pamSession
	if pamAvailable && !req.AgentAccount {
		if err := restoreStartFileLimit(); err != nil {
			closePTY()
			return refuse(launcher.CodePAMFailed, err)
		}
		rhost, _, _ := launcher.SplitClientAddr(req.ClientAddr)
		pam, err = openPAM(a.Name, pamTTY, rhost, a.GID, msgs)
		if err != nil {
			closePTY()
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
		args: shellArgs(shell, req),
		env:  sessionEnv(a, shell, req.Term, loginDefsPath(a.UID), req.ClientAddr, pamEnv, req.Env),
		dir:  workDir(a.Home),
		// With PAM the groups are already this process's: initgroups, then
		// pam_setcred.
		cred: &syscall.Credential{Uid: a.UID, Gid: a.GID, Groups: a.Groups, NoSetGroups: pam != nil && pamAvailable},
	}
	if req.Kind == launcher.KindSFTP {
		// The file server is this binary run as the login, as sshd runs
		// sftp-server: confined to files_root or the login's home.
		if plan.path, err = os.Executable(); err != nil {
			pam.close()
			return refuse(launcher.CodeSpawnFailed, err)
		}
		root := req.Root
		if root == "" {
			root = a.Home
		}
		access := FilesAccess{Download: req.FilesDownload, Upload: req.FilesUpload}
		plan.args, plan.events = []string{"localport-session", FilesServerMode, access.Arg(), root}, true
	}
	if req.Kind == launcher.KindForward {
		// The forward server takes the channel itself: it passes connected
		// sockets to the agent as descriptors, so nothing is relayed here.
		cmd, logDone, err := startForwardServer(channel, plan, req.Login, log)
		if err != nil {
			pam.close()
			return refuse(launcher.CodeSpawnFailed, err)
		}
		_ = channel.Close()
		if err := launcher.WriteHelperReply(control, launcher.HelperReply{Started: true, Messages: msgs.messages()}); err != nil {
			log("sessionhelper: reply started: %v", err)
		}
		_ = control.Close()
		<-logDone
		_ = cmd.Wait()
		pam.close()
		return 0
	}
	out := &frameWriter{w: channel}
	var k helperSession
	var ut *utmpEntry // nil without a PTY; logout is then a no-op
	if usePTY {
		t, err := startTerminal(out, master, slave, plan, log)
		if err != nil {
			pam.close()
			closePTY()
			return refuse(launcher.CodeSpawnFailed, err)
		}
		ut = utmpLogin(slave.Name(), a.Name, utmpHost(req.ClientAddr), t.cmd.Process.Pid)
		k = t
	} else {
		p, err := startPipeSession(out, plan, log)
		if err != nil {
			pam.close()
			return refuse(launcher.CodeSpawnFailed, err)
		}
		k = p
	}
	if err := launcher.WriteHelperReply(control, launcher.HelperReply{Started: true, Messages: msgs.messages()}); err != nil {
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
	case <-k.endedC():
	case <-inputDone:
	}
	k.finish()
	k.Wait()
	ut.logout()
	pam.close()
	_ = channel.Close()
	return 0
}

// helperSession is a running session: a terminal on a PTY or an exec
// session on pipes.
type helperSession interface {
	handle(f launcher.Frame) error
	endedC() <-chan struct{}
	finish()
	Wait()
}

// startForwardServer starts the forward server as plan's user with channel on
// its descriptor 3; the server dials and listens as that user and passes
// each connected socket to the agent over channel. Its stderr is relayed to
// log until logDone closes, which the caller waits for before cmd.Wait.
func startForwardServer(channel *os.File, plan spawnPlan, login string, log func(string, ...any)) (cmd *exec.Cmd, logDone <-chan struct{}, err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	cmd = &exec.Cmd{
		Path:        exe,
		Args:        []string{"localport-session", ForwardServerMode},
		Env:         plan.env,
		Dir:         plan.dir,
		ExtraFiles:  []*os.File{channel},
		SysProcAttr: &syscall.SysProcAttr{Setsid: true, Credential: plan.cred},
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := startChild(cmd); err != nil {
		return nil, nil, err
	}
	done := make(chan struct{})
	prefix := fmt.Sprintf("sessionhelper: forward server %d for %q:", cmd.Process.Pid, login)
	go func() {
		defer close(done)
		relayChildLog(stderr, prefix, log)
	}()
	return cmd, done, nil
}

const (
	// maxChildLogLine bounds one relayed line; the rest of a longer line is
	// dropped.
	maxChildLogLine = 1 << 10
	// maxChildLogBytes bounds what one child may write to the helper's log.
	maxChildLogBytes = 64 << 10
)

// relayChildLog writes each line r carries to log, %q-quoted after prefix:
// the child runs as the login, so its text is untrusted and must not forge
// log lines. Past maxChildLogBytes it logs one notice and drains r unread
// until EOF, so the child never blocks on a full pipe.
func relayChildLog(r io.Reader, prefix string, log func(string, ...any)) {
	br := bufio.NewReaderSize(r, maxChildLogLine)
	total := 0
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			long := errors.Is(err, bufio.ErrBufferFull)
			total += len(line)
			if total > maxChildLogBytes {
				log("%s output over %d bytes dropped", prefix, maxChildLogBytes)
				_, _ = io.Copy(io.Discard, br)
				return
			}
			log("%s %q", prefix, strings.TrimSuffix(string(line), "\n"))
			if long {
				// Skip the rest of the line.
				for errors.Is(err, bufio.ErrBufferFull) {
					line, err = br.ReadSlice('\n')
					total += len(line)
				}
			}
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// shellArgs is the shell's argv: a login shell ("-sh") for a terminal and
// for an exec session without a command, else `sh -c command`, as sshd
// runs a command.
func shellArgs(shell string, req launcher.HelperRequest) []string {
	if req.Kind == launcher.KindExec && req.Command != "" {
		return []string{filepath.Base(shell), "-c", req.Command}
	}
	return []string{"-" + filepath.Base(shell)}
}

// maxPAMMessageBytes bounds the PAM message text one session keeps; the
// reply then fits what is kept under launcher.MaxMessage.
const maxPAMMessageBytes = 8 << 10

// pamMessages collects the session setup's messages for the client: the
// informational and error messages PAM modules send (pam_nologin's text, an
// expiry warning, pam_motd) and, without PAM, the /etc/nologin text. They
// are sanitized for the client's terminal: invalid UTF-8 and control bytes other than tab and
// newline become U+FFFD.
type pamMessages struct {
	list  []string
	bytes int
}

func (m *pamMessages) add(s string) {
	if m == nil || s == "" || m.bytes >= maxPAMMessageBytes {
		return
	}
	s = strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t' && r != '\n') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(s, string(utf8.RuneError)))
	m.list = append(m.list, s)
	m.bytes += len(s)
}

// messages returns what was collected, fitted to the reply bound.
func (m *pamMessages) messages() []string {
	if m == nil {
		return nil
	}
	return launcher.FitMessages(m.list)
}

// errPAMAccount is an account refusal: by the PAM account stack (expired,
// locked, password change required, denied by policy), or by the checks a
// no-PAM build and every build apply (checkShadow, shellUsable).
var errPAMAccount = errors.New("account refused")

// checkShadow refuses a locked password field and an account on or past its
// expiry day (days since 1970-01-01, so 0 is expired; -1, an empty field, is
// none), as pam_unix and sshd's auth-shadow read it. Locked is a leading
// '!', as sshd's platform_locked_account on Linux (LOCKED_PASSWD_PREFIX);
// '*' alone only disables password logins, which these sessions never use.
func checkShadow(password string, expireDay int64, now time.Time) error {
	if strings.HasPrefix(password, "!") {
		return fmt.Errorf("%w: the account is locked", errPAMAccount)
	}
	if expireDay >= 0 && now.Unix()/86400 >= expireDay {
		return fmt.Errorf("%w: the account expired", errPAMAccount)
	}
	return nil
}

// nologinPath is the file whose presence stops the logins of every account
// but root; on a PAM build pam_nologin applies it to every login but the
// agent account's.
const nologinPath = "/etc/nologin"

// maxNologinText bounds the nologin text passed to the client.
const maxNologinText = 1 << 10

// nologinText is the start of the file at path, the text sshd prints for a
// login it refuses; empty when it cannot be read.
func nologinText(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxNologinText))
	return string(b)
}

// noteNologin adds the nologin file's text to msgs when err is a nologin
// refusal: the client sees it, as sshd prints it.
func noteNologin(msgs *pamMessages, err error, path string) {
	if errors.Is(err, errcode.New(errcode.LoginsDisabled)) {
		msgs.add(nologinText(path))
	}
}

// checkNologin refuses uid when the file at path exists and uid is not root,
// as sshd's do_nologin on a host without PAM.
func checkNologin(uid uint32, path string) error {
	if uid == 0 {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %w", errPAMAccount, errcode.New(errcode.LoginsDisabled))
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
// PATH, the client's origin (originEnv), then every variable PAM set, which
// overrides those of the same name, then the client's LANG and LC_*
// variables (launcher.ValidEnv, checked by Request.Validate), which override
// a PAM locale. Nothing comes from the launcher's or the agent's
// environment.
func sessionEnv(a account, shell, term, path, clientAddr string, pamEnv []string, clientEnv map[string]string) []string {
	env := map[string]string{
		"HOME": a.Home, "USER": a.Name, "LOGNAME": a.Name, "SHELL": shell,
		"TERM": term, "PATH": path,
	}
	order := []string{"HOME", "USER", "LOGNAME", "SHELL", "TERM", "PATH"}
	if term == "" {
		// A session without a terminal has no TERM, as under sshd.
		delete(env, "TERM")
		order = slices.Delete(order, 4, 5)
	}
	for _, kv := range launcher.OriginEnv(clientAddr) {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
		order = append(order, k)
	}
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
	for _, k := range slices.Sorted(maps.Keys(clientEnv)) {
		if _, seen := env[k]; !seen {
			order = append(order, k)
		}
		env[k] = clientEnv[k]
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+env[k])
	}
	return out
}

// startChild starts every process the helper runs. PAM modules and NSS open
// descriptors without O_CLOEXEC, so each start first marks every descriptor
// close-on-exec; the child gets only its standard descriptors and the
// ExtraFiles exec.Cmd duplicates into place.
func startChild(cmd *exec.Cmd) error {
	closeExtraFDs()
	return cmd.Start()
}

// closeExtraFDs makes every descriptor from 3 up close-on-exec.
func closeExtraFDs() {
	if closeRangeCloexec(3) == nil {
		return
	}
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err == nil && fd >= 3 {
			unix.CloseOnExec(fd)
		}
	}
}
