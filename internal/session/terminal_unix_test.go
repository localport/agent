//go:build linux || darwin

package session

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/security"
)

// fakeLoginExit is the status the test binary exits with when it runs as
// login(1) (argv0 "login", then -f), after printing its argv, environment and
// working directory.
const fakeLoginExit = 9

// leaderLogin is the ticket login for which the fake login(1) starts a shell
// in a session of its own on the terminal, as login(1) does, so the slave's
// session leader is not the spawned process.
const leaderLogin = "leader"

// holdSlaveArg makes the test binary a process outside the terminal's session
// that keeps the slave open, as setsid(1) with nohup(1) would; macOS has no
// setsid(1).
const holdSlaveArg = "localport-test-hold-slave"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[0] == "login" && os.Args[1] == "-f" && os.Args[2] == leaderLogin {
		os.Exit(runLeaderLogin())
	}
	if len(os.Args) == 2 && os.Args[1] == holdSlaveArg {
		// A job control shell made this process a group leader, which
		// setsid refuses, so the holder is a child in a new session; the
		// ignored SIGHUP is inherited.
		signal.Ignore(syscall.SIGHUP)
		hold := exec.Command(os.Args[0], holdSlaveArg+"-child")
		hold.Stdin, hold.Stdout, hold.Stderr = os.Stdin, os.Stdout, os.Stderr
		hold.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := hold.Start(); err != nil {
			fmt.Println("hold:", err)
			os.Exit(1)
		}
		fmt.Printf("HOLDER=%d\n", hold.Process.Pid)
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == holdSlaveArg+"-child" {
		time.Sleep(10 * time.Minute)
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[0] == "login" && os.Args[1] == "-f" {
		cwd, _ := os.Getwd()
		fmt.Printf("ARGV=%s\nENV=%s\nCWD=%s\n", strings.Join(os.Args, " "), strings.Join(os.Environ(), ","), cwd)
		os.Exit(fakeLoginExit)
	}
	os.Exit(m.Run())
}

const terminalStartBody = `{"cols":80,"rows":24}`

// terminalServer serves terminal tickets with the real terminal kind over
// host. With root false the agent is not root, so the kind runs the fake
// account's shell directly, as the test process's user.
func terminalServer(t *testing.T, host *terminalHost, root bool, shell string) (*testServer, *eventLog) {
	t.Helper()
	events := &eventLog{}
	ts := newTestServer(t, func(c *ServerConfig) { c.OnEvent = events.add })
	home := t.TempDir()
	ts.users = func(_ context.Context, login string) (*userRecord, error) {
		u := testUser(login, 1000)
		u.Home, u.Shell = home, shell
		return u, nil
	}
	ts.euid = func() int {
		if root {
			return 0
		}
		return 1000
	}
	ts.kinds = func(kind string) prepareKind {
		if kind == "terminal" {
			return host.prepare
		}
		return nil
	}
	return ts, events
}

// noLoginHost has no login(1) and no SELinux.
func noLoginHost(t *testing.T) *terminalHost {
	dir := t.TempDir()
	return &terminalHost{
		logins:         []string{filepath.Join(dir, "login")},
		selinuxEnforce: filepath.Join(dir, "enforce"),
		checkLogin:     func(string) error { return nil },
	}
}

// fakeLoginHost's login(1) is a symlink to the test binary, which acts as
// login when run with argv0 login.
func fakeLoginHost(t *testing.T) *terminalHost {
	h := noLoginHost(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, h.logins[0]); err != nil {
		t.Fatal(err)
	}
	return h
}

// shellSession opens a terminal session whose shell is /bin/sh.
func shellSession(t *testing.T) (*testServer, *testClient) {
	t.Helper()
	ts, _ := terminalServer(t, noLoginHost(t), false, "/bin/sh")
	return ts, ts.openStart(t, ts.ticket(t, nil), []byte(terminalStartBody))
}

func (c *testClient) send(t *testing.T, typ MessageType, body string) {
	t.Helper()
	if err := c.ch.WriteMessage(typ, []byte(body)); err != nil {
		t.Fatal(err)
	}
}

// readUntil reads data records until their concatenation matches re and
// returns the first submatch (the whole match without one).
func (c *testClient) readUntil(t *testing.T, re *regexp.Regexp) string {
	t.Helper()
	var out []byte
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = c.conn.SetReadDeadline(deadline)
		m, err := c.ch.ReadMessage()
		if err != nil || m.Type != TypeData {
			t.Fatalf("got %v %q, %v after output %q; want data matching %s", m.Type, m.Body, err, out, re)
		}
		if len(m.Body) > maxTerminalOutput {
			t.Fatalf("data record of %d bytes", len(m.Body))
		}
		out = append(out, m.Body...)
		if s := re.FindSubmatch(out); s != nil {
			return string(s[len(s)-1])
		}
	}
}

// expectExit reads data records up to exit, requires its code and then
// close {exited} as the next record.
func (c *testClient) expectExit(t *testing.T, code int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = c.conn.SetReadDeadline(deadline)
		m, err := c.ch.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for exit: %v", err)
		}
		if m.Type == TypeData {
			continue
		}
		var b struct{ Code int }
		if m.Type != TypeExit || json.Unmarshal(m.Body, &b) != nil || b.Code != code {
			t.Fatalf("got %v %q; want exit {code: %d}", m.Type, m.Body, code)
		}
		break
	}
	c.expectClose(t, CloseExited)
}

func TestTerminalRoundTrip(t *testing.T) {
	_, c := shellSession(t)
	c.send(t, TypeData, "stty size; echo SIZE-DONE\n")
	if got := c.readUntil(t, regexp.MustCompile(`(\d+ \d+)\r\nSIZE-DONE`)); got != "24 80" {
		t.Fatalf("initial size %q, want 24 80", got)
	}
	c.send(t, TypeResize, `{"cols":100,"rows":40}`)
	c.send(t, TypeData, "stty size; echo SIZE-DONE\n")
	if got := c.readUntil(t, regexp.MustCompile(`(\d+ \d+)\r\nSIZE-DONE`)); got != "40 100" {
		t.Fatalf("size after resize %q, want 40 100", got)
	}
	c.send(t, TypeData, "echo hello-$((6*7))\n")
	c.readUntil(t, regexp.MustCompile(`hello-42`))
	c.send(t, TypeData, "exit 7\n")
	c.expectExit(t, 7)
	waitDone(t, c.done)
}

// A recorded terminal session's segments hold the shell's output, the resize
// and the exit status.
func TestTerminalRecordsOutputResizeAndExit(t *testing.T) {
	ts, _ := terminalServer(t, noLoginHost(t), false, "/bin/sh")
	rs := recordSessions(t, ts, RecPolicyBestEffort, true)
	c := ts.openStart(t, ts.ticket(t, rs.ticket), []byte(terminalStartBody))
	c.send(t, TypeResize, `{"cols":100,"rows":40}`)
	c.send(t, TypeData, "stty size; echo rec-$((6*7))\n")
	c.readUntil(t, regexp.MustCompile(`40 100\r\nrec-42`))
	c.send(t, TypeData, "exit 7\n")
	c.expectExit(t, 7)
	waitDone(t, c.done)
	segs, wrapped := rs.edge.completedRecording(t)
	text := decryptRecording(t, rs.priv, wrapped, segs)
	for _, re := range []string{`"o", ?"[^"]*rec-42`, `"r", ?"100x40"`, `"x", ?"7"`} {
		if !regexp.MustCompile(re).MatchString(text) {
			t.Errorf("recording lacks %s:\n%s", re, text)
		}
	}
}

// No variable of the agent's environment reaches the shell.
func TestTerminalShellGetsNoAgentEnvironment(t *testing.T) {
	for _, name := range []string{"INVOCATION_ID", "XPC_SERVICE_NAME", "LISTEN_FDS", "LOCALPORT_TERMINAL_SENTINEL"} {
		t.Setenv(name, "agent-value")
	}
	_, c := shellSession(t)
	c.send(t, TypeData, "echo ENV-BEGIN; env; echo ENV-END\n")
	env := c.readUntil(t, regexp.MustCompile(`(?s)ENV-BEGIN\r\n(.*)ENV-END`))
	for _, name := range []string{"INVOCATION_ID", "XPC_SERVICE_NAME", "LISTEN_FDS", "LOCALPORT_TERMINAL_SENTINEL"} {
		if strings.Contains(env, name+"=") {
			t.Errorf("the shell has %s:\n%s", name, env)
		}
	}
	// PATH is left out: the login shell's profile rewrites it.
	for _, want := range []string{"TERM=xterm-256color", "USER=pi", "LOGNAME=pi", "SHELL=/bin/sh", "HOME=/"} {
		if !strings.Contains(env, want) {
			t.Errorf("the shell lacks %s:\n%s", want, env)
		}
	}
	c.send(t, TypeData, "exit\n")
	c.expectExit(t, 0)
}

// Only the PTY slave reaches the shell: a non-interactive child of it, which
// inherits every fd without close-on-exec, holds 0, 1 and 2, plus the
// directory its own glob opens. (An interactive bash keeps a close-on-exec
// copy of the terminal at fd 255.)
func TestTerminalShellHoldsOnlyTheSlave(t *testing.T) {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	_, c := shellSession(t)
	c.send(t, TypeData, "sh -c 'cd "+dir+" && echo FDS= * END'\n")
	got := strings.Fields(c.readUntil(t, regexp.MustCompile(`FDS= ([0-9 ]*) END`)))
	extra := slices.DeleteFunc(slices.Clone(got), func(s string) bool { return s == "0" || s == "1" || s == "2" })
	if len(got) != 4 || len(extra) != 1 {
		t.Fatalf("fds %v, want 0 1 2 and the listing's own", got)
	}
	c.send(t, TypeData, "exit\n")
	c.expectExit(t, 0)
}

// The shell leads its own session and process group.
func TestTerminalShellHasItsOwnSession(t *testing.T) {
	_, c := shellSession(t)
	c.send(t, TypeData, "echo PID=$$; read x\n")
	pid, err := strconv.Atoi(c.readUntil(t, regexp.MustCompile(`PID=(\d+)\r\n`)))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		t.Fatal(err)
	}
	pgid, err := unix.Getpgid(pid)
	if err != nil {
		t.Fatal(err)
	}
	ownSid, _ := unix.Getsid(0)
	if sid != pid || sid == ownSid || pgid == unix.Getpgrp() {
		t.Fatalf("shell %d: sid %d pgid %d; agent sid %d pgid %d", pid, sid, pgid, ownSid, unix.Getpgrp())
	}
	c.send(t, TypeData, "\nexit 0\n")
	c.expectExit(t, 0)
}

// Output arriving after the process exited (a background job still writing
// to the terminal) is drained within its bound, and no data record follows
// exit.
func TestTerminalSendsNoDataAfterExit(t *testing.T) {
	_, c := shellSession(t)
	// On macOS the kernel revokes the terminal when the shell, its session
	// leader, exits, so the job's output ends there; on Linux it keeps
	// writing until the end path closes the master.
	c.send(t, TypeData, "sh -c 'echo JOB=$$; exec yes' & sleep 0.2; exit 3\n")
	if pid, err := strconv.Atoi(c.readUntil(t, regexp.MustCompile(`JOB=(\d+)\r\n`))); err == nil {
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	}
	c.expectExit(t, 3)
	waitDone(t, c.done)
}

// A process that does not start ends the session after the spend with a
// reason, exit 127 and close {exited}.
func TestTerminalStartFailure(t *testing.T) {
	ts, events := terminalServer(t, noLoginHost(t), false, "/nonexistent/sh")
	c := ts.openStart(t, ts.ticket(t, nil), []byte(terminalStartBody))
	// The remote user sees a fixed line; the cause, which names device paths,
	// stays in the device's log.
	if out := c.readUntil(t, regexp.MustCompile(`(?s)(.*did not start.*)\r\n`)); strings.Contains(out, "/nonexistent") {
		t.Fatalf("the session shows the cause: %q", out)
	}
	c.expectExit(t, terminalStartFailedCode)
	if !events.has("/nonexistent/sh") {
		t.Fatalf("the cause was not logged: %q", events.lines)
	}
	if !ts.spent(ts.f.payload().JTI) {
		t.Fatal("the ticket is not spent")
	}
}

// The agent ending the session (Shutdown) hangs up the shell and reaps it.
func TestTerminalShutdownEndsTheShell(t *testing.T) {
	ts, c := shellSession(t)
	c.send(t, TypeData, "echo READY; read x\n")
	c.readUntil(t, regexp.MustCompile(`READY\r\n`))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := ts.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitDone(t, c.done)
}

// The end path releases an output tap waiting on a full Strict recording
// queue at once, so the reader joins without waiting out strictBackpressure.
func TestTerminalEndReleasesAStrictRecordingWait(t *testing.T) {
	r, _, _ := stallRecorder(t, RecPolicyStrict)
	agentSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close() })
	go func() { _, _ = io.Copy(io.Discard, clientSide) }()
	key := make([]byte, 32)
	ch, err := newChannel(agentSide, key, key)
	if err != nil {
		t.Fatal(err)
	}
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", "echo blocked; exec sleep 30"}, home: t.TempDir()}
	k, ok := startTerminal(ch, plan, terminalStart{terminalSize: terminalSize{Cols: 80, Rows: 24}, Term: "xterm"}, t.Logf, r).(*terminal)
	if !ok {
		t.Fatal("the terminal did not start")
	}
	select {
	case <-k.readerDone:
		t.Fatal("the reader did not wait on the full Strict queue")
	case <-time.After(300 * time.Millisecond):
	}
	k.End()
	select {
	case <-k.readerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the end path did not release the Strict wait")
	}
	k.Wait()
}

// The end hangs up the terminal: a child in the foreground group that does
// not ignore SIGHUP exits at once, also on macOS, where the revoke of the
// slave keeps the kernel's own hangup from reaching the session. The exec
// leaves a non-interactive sh as the spawned process, which forwards no
// SIGHUP to its child, and its exit skips the group SIGKILL.
func TestTerminalEndHangsUpTheForegroundGroup(t *testing.T) {
	ts, c := shellSession(t)
	c.send(t, TypeData, "exec /bin/sh -c 'sleep 600 & echo CHILD=$!; wait'\n")
	m := regexp.MustCompile(`CHILD=(\d+)\r\n`).FindStringSubmatch(c.readUntil(t, regexp.MustCompile(`CHILD=\d+\r\n`)))
	child, _ := strconv.Atoi(m[1])
	t.Cleanup(func() { _ = syscall.Kill(child, syscall.SIGKILL) })
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := ts.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitDone(t, c.done)
	for deadline := time.Now().Add(2 * time.Second); !gone(child); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the shell's background job %d survived the hangup", child)
		}
	}
}

// As root the kind runs login -f <login> at the resolved login(1) path,
// argv0 login, with only TERM and cwd /. Its non-zero exit ends the session
// as exit {code}, with no other path tried.
func TestTerminalRunsLoginAsRoot(t *testing.T) {
	ts, _ := terminalServer(t, fakeLoginHost(t), true, "/bin/sh")
	c := ts.openStart(t, ts.ticket(t, nil), []byte(`{"cols":80,"rows":24,"term":"vt100"}`))
	out := c.readUntil(t, regexp.MustCompile(`(?s)(ARGV=.*CWD=\S*)\r\n`))
	for _, want := range []string{"ARGV=login -f pi\r\n", "ENV=TERM=vt100\r\n", "CWD=/"} {
		if !strings.Contains(out, want) {
			t.Fatalf("fake login printed %q, want %q", out, want)
		}
	}
	c.expectExit(t, fakeLoginExit)
	waitDone(t, c.done)
}

// A login(1) failing the ownership check, a missing login(1) and SELinux
// enforcing each refuse kind_unavailable before the spend, logged: a root
// session never starts a shell without the host's PAM stacks.
func TestTerminalRefusesWithoutAUsableLogin(t *testing.T) {
	owned := fakeLoginHost(t)
	exe, _ := filepath.EvalSymlinks(owned.logins[0])
	owned.checkLogin = func(path string) error {
		if path != exe {
			t.Errorf("checked %s, want the resolved %s", path, exe)
		}
		return security.CheckServiceBinary(path)
	}
	selinux := fakeLoginHost(t)
	if err := os.WriteFile(selinux.selinuxEnforce, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		host   *terminalHost
		logged string
	}{
		{"ownership", owned, "login(1): " + owned.logins[0]},
		{"no login", noLoginHost(t), ": no login(1) [AG052]"},
		{"selinux", selinux, "login(1): SELinux is enforcing [AG051]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, events := terminalServer(t, tc.host, true, "/bin/sh")
			if got := ts.refusal(t, ts.ticket(t, nil)); got != CodeKindUnavailable {
				t.Fatalf("refused %q, want kind_unavailable", got)
			}
			if ts.spent(ts.f.payload().JTI) {
				t.Fatal("the refusal spent the ticket")
			}
			if ts.LiveSessions() != 0 {
				t.Fatal("the refusal kept its slot")
			}
			if !events.has(tc.logged) {
				t.Fatalf("no log line with %q", tc.logged)
			}
		})
	}
}

// runLeaderLogin is the fake login(1) for leaderLogin: it prints its pid and
// waits for a shell that survives SIGHUP with a trap and keeps a child in its
// foreground group that does not ignore SIGHUP. On Linux, as util-linux
// login(1) does, it gives up the terminal (TIOCNOTTY, whose SIGHUP to its own
// group it catches) and the shell leads a session of its own on it; catching,
// unlike ignoring, does not reach the shell across exec. On macOS, as its
// login(1) does, it stays the session leader and the shell runs in a
// foreground process group of its own: XNU refuses TIOCNOTTY to a session
// leader.
func runLeaderLogin() int {
	fmt.Printf("LOGIN=%d\n", os.Getpid())
	attr := &syscall.SysProcAttr{Setpgid: true, Foreground: true, Ctty: 0}
	if runtime.GOOS == "linux" {
		signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP)
		if err := unix.IoctlSetInt(0, unix.TIOCNOTTY, 0); err != nil {
			fmt.Printf("TIOCNOTTY: %v\n", err)
			return 1
		}
		signal.Reset(syscall.SIGHUP)
		attr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	cmd := exec.Command("/bin/sh", "-c", `trap ':' HUP; sleep 600 & echo "SHELL=$$ CHILD=$!"; while :; do sleep 1; done`)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = attr
	if err := cmd.Run(); err != nil {
		fmt.Printf("leader: %v\n", err)
		return 1
	}
	return 0
}

// skipToClose reads records up to the agent's close, skipping data, and
// requires its reason.
func (c *testClient) skipToClose(t *testing.T, reason string) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	for {
		m, err := c.ch.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for close %q: %v", reason, err)
		}
		if m.Type == TypeData {
			continue
		}
		if m.Type != TypeClose || m.Reason != reason {
			t.Fatalf("got %v %q; want close %q", m.Type, m.Reason, reason)
		}
		return
	}
}

// shutdown ends the session with Shutdown, reads up to close {shutdown} as
// the edge does, ends the stream, and returns the time until Serve returned.
func (c *testClient) shutdown(t *testing.T, ts *testServer, within time.Duration) time.Duration {
	t.Helper()
	begin := time.Now()
	errc := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), within)
		defer cancel()
		errc <- ts.Shutdown(ctx)
	}()
	c.skipToClose(t, CloseShutdown)
	_ = c.conn.Close()
	if err := <-errc; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	waitDone(t, c.done)
	return time.Since(begin)
}

// terminalGoroutines returns the stacks of the terminal kind's reader and
// waiter goroutines still running.
func terminalGoroutines() []string {
	buf := make([]byte, 4<<20)
	buf = buf[:runtime.Stack(buf, true)]
	var found []string
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "session.(*terminal).readOutput(") || strings.Contains(g, "session.(*terminal).wait(") {
			found = append(found, g)
		}
	}
	return found
}

// endBound is how long after the end decision a blocked master Read or Write
// returns: 1 s after the master's close on Linux; on macOS before the
// SIGKILL, whose session leader exit would revoke the terminal by itself.
func endBound() time.Duration {
	if runtime.GOOS == "darwin" {
		return terminalKillDelay - time.Second
	}
	return time.Second
}

// goneAfter reports, once no goroutine runs frame, the time since begin.
func goneAfter(frame string, begin time.Time) <-chan time.Duration {
	took := make(chan time.Duration, 1)
	go func() {
		for {
			buf := make([]byte, 4<<20)
			if !strings.Contains(string(buf[:runtime.Stack(buf, true)]), frame) {
				took <- time.Since(begin)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return took
}

// A process outside the session holding the slave does not keep the reader
// alive: with a shell that ignores SIGHUP, so its exit does not end the read,
// the reader returns within endBound, and the reader and waiter goroutines
// have returned when Serve does.
func TestTerminalEndJoinsTheReaderWhileAnotherSessionHoldsTheSlave(t *testing.T) {
	ts, c := shellSession(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c.send(t, TypeData, "trap '' HUP; '"+exe+"' "+holdSlaveArg+" &\n")
	pid, err := strconv.Atoi(c.readUntil(t, regexp.MustCompile(`HOLDER=(\d+)\r\n`)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	readerGone := goneAfter("session.(*terminal).readOutput(", time.Now())
	c.shutdown(t, ts, 10*time.Second)
	if took := <-readerGone; took > endBound() {
		t.Fatalf("the reader returned %v after the end, want at most %v", took, endBound())
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the holder outside the session did not survive: %v", err)
	}
	if g := terminalGoroutines(); len(g) > 0 {
		t.Fatalf("terminal goroutines still running after the end:\n%s", strings.Join(g, "\n\n"))
	}
}

// A master write blocked by input backpressure (the terminal's process
// reads nothing and ignores SIGHUP) returns within endBound of the end.
func TestTerminalEndInterruptsABlockedInputWrite(t *testing.T) {
	ts, c := shellSession(t)
	c.send(t, TypeData, "trap '' HUP; stty raw -echo; echo RAW; exec sleep 600\n")
	c.readUntil(t, regexp.MustCompile(`RAW\r?\n`))
	var sent atomic.Int64
	go func() {
		chunk := []byte(strings.Repeat("x", 4096))
		for c.ch.WriteMessage(TypeData, chunk) == nil {
			sent.Add(int64(len(chunk)))
		}
	}()
	// Backpressure reached: the client's writes stall once the agent's
	// session reader is blocked in the master write.
	deadline := time.Now().Add(10 * time.Second)
	for last := int64(-1); ; {
		time.Sleep(300 * time.Millisecond)
		n := sent.Load()
		if n == last && n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("input never stalled after %d bytes", n)
		}
		last = n
	}
	handleGone := goneAfter("session.(*terminal).Handle(", time.Now())
	c.shutdown(t, ts, 10*time.Second)
	if took := <-handleGone; took > endBound() {
		t.Fatalf("the blocked input write returned %v after the end, want at most %v", took, endBound())
	}
}

// A process that is not reaped after the SIGKILL (the exit observer blocks,
// as for a process in uninterruptible sleep) does not hold the session: Wait
// returns terminalReapTimeout after the SIGKILL, logged, and the waiter
// reaps the process once it can.
func TestTerminalJoinIsBoundedForAnUnreapedProcess(t *testing.T) {
	release := make(chan struct{})
	prev := observeExit
	observeExit = func(pid int) error {
		<-release
		return waitExited(pid)
	}
	t.Cleanup(func() {
		observeExit = prev
		close(release)
		deadline := time.Now().Add(5 * time.Second)
		for len(terminalGoroutines()) > 0 {
			if time.Now().After(deadline) {
				t.Errorf("the detached waiter did not return:\n%s", strings.Join(terminalGoroutines(), "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	ts, events := terminalServer(t, noLoginHost(t), false, "/bin/sh")
	c := ts.openStart(t, ts.ticket(t, nil), []byte(terminalStartBody))
	c.send(t, TypeData, "echo READY\n")
	c.readUntil(t, regexp.MustCompile(`READY\r\n`))
	took := c.shutdown(t, ts, 10*time.Second)
	if took < terminalKillDelay || took > terminalKillDelay+terminalReapTimeout+time.Second {
		t.Fatalf("the session ended %v after Shutdown, want %v after the SIGKILL at %v", took, terminalReapTimeout, terminalKillDelay)
	}
	if !events.has("not reaped 1s after SIGKILL; a detached reaper owns it") {
		t.Fatal("the unreaped process was not logged")
	}
}

// The SIGKILL step never signals the spawned process's group once its exit
// was observed: the group number may belong to another process by then.
// The live group here stands for such a reused number.
func TestTerminalKillSkipsAnObservedExit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	k := &terminal{cmd: cmd, exitSeen: true, killDone: make(chan struct{})}
	k.killSession()
	for range 50 {
		var ws unix.WaitStatus
		if pid, _ := unix.Wait4(cmd.Process.Pid, &ws, unix.WNOHANG, nil); pid != 0 {
			t.Fatalf("the group was signalled after the observed exit: %v", ws)
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-k.killDone:
	default:
		t.Fatal("the SIGKILL step did not finish")
	}
}

// When the exit cannot be observed, the SIGKILL step kills the spawned
// process itself and spares its group, whose number the reap may free. The
// second member stands for a process of a reused group.
func TestTerminalKillSparesTheGroupOfAnUnobservedExit(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	member := exec.Command("/bin/sleep", "60")
	member.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: cmd.Process.Pid}
	if err := member.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = member.Process.Kill()
		_ = member.Wait()
	})
	k := &terminal{cmd: cmd, exitUnobserved: true, killDone: make(chan struct{})}
	k.killSession()
	_ = cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the spawned process ended with %v, want SIGKILL", cmd.ProcessState)
	}
	var ws unix.WaitStatus
	if pid, _ := unix.Wait4(member.Process.Pid, &ws, unix.WNOHANG, nil); pid != 0 {
		t.Fatalf("the group was signalled after an unobserved exit: %v", ws)
	}
}

// gone reports whether pid no longer runs. On Linux a zombie counts as gone
// (an orphan in a container whose init does not reap); launchd reaps
// orphans on macOS.
func gone(pid int) bool {
	if runtime.GOOS != "linux" {
		return syscall.Kill(pid, 0) != nil
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	i := strings.LastIndexByte(string(stat), ')')
	return i < 0 || i+2 >= len(stat) || stat[i+2] == 'Z'
}

// After an end, the spawned process, the slave's session leader (which
// survived SIGHUP and the hangup) and the shell's child that did not ignore
// SIGHUP are gone. On Linux the shell is the session leader; on macOS the
// spawned login is, and the shell, a foreground group that survived SIGHUP,
// is left alone as any such job is. Root only (make test-root runs every
// TestRoot test): the kind runs login(1) only as root.
func TestRootTerminalEndLeavesNoSessionProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (make test-root)")
	}
	ts, _ := terminalServer(t, fakeLoginHost(t), true, "/bin/sh")
	ts.cfg.Logins = append(ts.cfg.Logins, leaderLogin)
	c := ts.openStart(t, ts.ticket(t, func(p *Ticket) { p.Login = leaderLogin }), []byte(terminalStartBody))
	var login, shell, child int
	out := c.readUntil(t, regexp.MustCompile(`LOGIN=\d+\r\nSHELL=\d+ CHILD=\d+`))
	if _, err := fmt.Sscanf(out, "LOGIN=%d\r\nSHELL=%d CHILD=%d", &login, &shell, &child); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	t.Cleanup(func() {
		for _, pid := range []int{login, shell, child} {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	c.shutdown(t, ts, 10*time.Second)
	type process struct {
		name string
		pid  int
	}
	gonePs := []process{{"spawned login and session leader", login}, {"shell's child", child}}
	if runtime.GOOS == "linux" {
		gonePs = []process{{"spawned login", login}, {"shell and session leader", shell}, {"shell's child", child}}
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, p := range gonePs {
		for !gone(p.pid) {
			if time.Now().After(deadline) {
				t.Fatalf("the %s %d survived the end", p.name, p.pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// openResetShell opens a terminal session whose shell is /bin/sh over a
// resetStream, the tunnel's session stream semantics.
func openResetShell(t *testing.T) (*testServer, *testClient) {
	t.Helper()
	ts, _ := terminalServer(t, noLoginHost(t), false, "/bin/sh")
	return ts, ts.openResetStart(t, ts.ticket(t, nil), []byte(terminalStartBody))
}

// Over a stream that resets on Close and on an expired deadline, a terminal
// round trip delivers the exit record and close {exited} before the reset.
func TestTerminalRoundTripOverAResetStream(t *testing.T) {
	_, c := openResetShell(t)
	c.send(t, TypeData, "stty size; echo SIZE-DONE\n")
	if got := c.readUntil(t, regexp.MustCompile(`(\d+ \d+)\r\nSIZE-DONE`)); got != "24 80" {
		t.Fatalf("initial size %q, want 24 80", got)
	}
	c.send(t, TypeResize, `{"cols":100,"rows":40}`)
	c.send(t, TypeData, "stty size; echo SIZE-DONE\n")
	if got := c.readUntil(t, regexp.MustCompile(`(\d+ \d+)\r\nSIZE-DONE`)); got != "40 100" {
		t.Fatalf("size after resize %q, want 40 100", got)
	}
	c.send(t, TypeData, "echo hello-$((6*7))\n")
	c.readUntil(t, regexp.MustCompile(`hello-42`))
	c.send(t, TypeData, "exit 7\n")
	c.expectExit(t, 7)
	_ = c.conn.Close()
	waitDone(t, c.done)
}

// The idle and Shutdown ends of a terminal session deliver their close
// record over a resetStream before the reset.
func TestTerminalAgentEndsOverAResetStream(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		ts, c := openResetShell(t)
		c.send(t, TypeData, "echo READY\n")
		c.readUntil(t, regexp.MustCompile(`READY\r\n`))
		ts.clock.waitArmed(t)
		ts.clock.Advance(idleTimeout)
		ts.clock.Fire()
		c.skipToClose(t, CloseIdle)
		_ = c.conn.Close()
		waitDone(t, c.done)
	})
	t.Run("shutdown", func(t *testing.T) {
		ts, c := openResetShell(t)
		c.send(t, TypeData, "echo READY\n")
		c.readUntil(t, regexp.MustCompile(`READY\r\n`))
		c.shutdown(t, ts, 10*time.Second)
	})
}
