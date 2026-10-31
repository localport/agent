//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"errors"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/launcher"
)

// shell is a terminal running /bin/sh as the test's user, read through the
// agent's end of the channel.
type shell struct {
	k   *terminal
	fr  *launcher.FrameReader
	in  *os.File
	buf strings.Builder
}

func startShell(t *testing.T) *shell {
	t.Helper()
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	master, slave, err := openPTY(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	plan := spawnPlan{path: "/bin/sh", args: []string{"-sh"}, env: []string{"PATH=/usr/bin:/bin", "TERM=dumb", "HOME=/", "PS1=$ "}, dir: "/"}
	k, err := startTerminal(&frameWriter{w: helper}, master, slave, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		k.finish()
		k.Wait()
		agent.Close()
		helper.Close()
	})
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	return &shell{k: k, fr: launcher.NewFrameReader(agent), in: agent}
}

func (s *shell) send(t *testing.T, line string) {
	t.Helper()
	if err := s.k.handle(launcher.Frame{Type: launcher.FrameData, Data: []byte(line)}); err != nil {
		t.Fatal(err)
	}
}

// readUntil reads data frames until re matches the output so far and
// returns its first group.
func (s *shell) readUntil(t *testing.T, re *regexp.Regexp) string {
	t.Helper()
	for {
		if m := re.FindStringSubmatch(s.buf.String()); m != nil {
			return m[1]
		}
		f, err := s.fr.ReadFrame()
		if err != nil {
			t.Fatalf("read %q: %v; output so far %q", re, err, s.buf.String())
		}
		if f.Type == launcher.FrameExit {
			t.Fatalf("exit %d before %q; output %q", f.Code, re, s.buf.String())
		}
		s.buf.Write(f.Data)
	}
}

// expectExit skips output to the exit frame and requires code, then that
// no frame follows it.
func (s *shell) expectExit(t *testing.T, code int32) {
	t.Helper()
	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			t.Fatalf("no exit frame: %v", err)
		}
		if f.Type == launcher.FrameExit {
			if f.Code != code {
				t.Fatalf("exit %d, want %d", f.Code, code)
			}
			break
		}
	}
	select {
	case <-s.k.ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal did not end after its exit frame")
	}
}

func TestTerminalRoundTripAndExitCode(t *testing.T) {
	s := startShell(t)
	s.send(t, "echo hi-$((1+2))\n")
	s.readUntil(t, regexp.MustCompile(`(hi-3)\r\n`))
	if err := s.k.handle(launcher.Frame{Type: launcher.FrameResize, Cols: 120, Rows: 40}); err != nil {
		t.Fatal(err)
	}
	s.send(t, "stty size\n")
	s.readUntil(t, regexp.MustCompile(`(40 120)`))
	s.send(t, "exit 5\n")
	s.expectExit(t, 5)
}

// The shell holds only its PTY: no channel, control or other descriptor of
// the helper leaks into it.
func TestTerminalShellHoldsOnlyThePTY(t *testing.T) {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	s := startShell(t)
	s.send(t, "sh -c 'cd "+dir+" && echo FDS= * END'\n")
	got := strings.Fields(s.readUntil(t, regexp.MustCompile(`FDS= ([0-9 ]*) END`)))
	extra := slices.DeleteFunc(slices.Clone(got), func(f string) bool { return f == "0" || f == "1" || f == "2" })
	if len(got) != 4 || len(extra) != 1 {
		t.Fatalf("fds %v, want 0 1 2 and the listing's own", got)
	}
	s.send(t, "exit\n")
	s.expectExit(t, 0)
}

// The shell leads its own session and process group.
func TestTerminalShellHasItsOwnSession(t *testing.T) {
	s := startShell(t)
	s.send(t, "echo PID=$$\n")
	pid, err := strconv.Atoi(s.readUntil(t, regexp.MustCompile(`PID=(\d+)\r\n`)))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		t.Fatal(err)
	}
	ownSid, _ := unix.Getsid(0)
	if sid != pid || sid == ownSid {
		t.Fatalf("shell %d: sid %d; test sid %d", pid, sid, ownSid)
	}
	s.send(t, "exit 0\n")
	s.expectExit(t, 0)
}

// The end path ends a shell that ignores SIGHUP with the SIGKILL step, and
// sends no exit frame for an end it decided.
func TestTerminalEndKillsAShellIgnoringHangup(t *testing.T) {
	s := startShell(t)
	s.send(t, "trap '' HUP; echo READY=$$; while :; do sleep 1; done\n")
	pid, err := strconv.Atoi(s.readUntil(t, regexp.MustCompile(`READY=(\d+)\r\n`)))
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	s.k.finish()
	s.k.Wait()
	if took := time.Since(begin); took > terminalKillDelay+3*time.Second {
		t.Fatalf("end took %v", took)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("shell %d still exists after the end: %v", pid, err)
	}
	for {
		f, err := s.fr.ReadFrame()
		if err != nil {
			break
		}
		if f.Type == launcher.FrameExit {
			t.Fatal("an exit frame followed an end the helper decided")
		}
	}
}

func TestParseLoginDefsPath(t *testing.T) {
	defs := "# comment\nENV_SUPATH PATH=/usr/sbin:/usr/bin\nENV_PATH   /usr/local/bin:/usr/bin\n"
	if got := parseLoginDefsPath(defs, 0); got != "/usr/sbin:/usr/bin" {
		t.Errorf("root PATH %q", got)
	}
	if got := parseLoginDefsPath(defs, 1000); got != "/usr/local/bin:/usr/bin" {
		t.Errorf("user PATH %q", got)
	}
	if got := parseLoginDefsPath("UMASK 022\n", 1000); got != defaultPath {
		t.Errorf("no ENV_PATH: %q", got)
	}
}

// PAM's variables come after the login's and override the same name;
// nothing else is added.
func TestSessionEnv(t *testing.T) {
	a := account{Name: "pi", Home: "/home/pi"}
	got := sessionEnv(a, "/bin/bash", "xterm", "/usr/bin", []string{"XDG_SESSION_ID=4", "PATH=/pam/bin", "bad", "=x"})
	want := []string{"HOME=/home/pi", "USER=pi", "LOGNAME=pi", "SHELL=/bin/bash", "TERM=xterm", "PATH=/pam/bin", "XDG_SESSION_ID=4"}
	if !slices.Equal(got, want) {
		t.Fatalf("env %q, want %q", got, want)
	}
}

func TestCheckShadow(t *testing.T) {
	now := time.Unix(20000*86400, 0)
	for _, tc := range []struct {
		password string
		expire   int64
		refused  bool
	}{
		{"$6$salt$hash", -1, false},
		{"*", 0, false},
		{"", 0, false},
		{"!$6$salt$hash", 0, true},
		{"!", 0, true},
		{"$6$x", 20000, true},
		{"$6$x", 20001, false},
	} {
		err := checkShadow(tc.password, tc.expire, now)
		if (err != nil) != tc.refused || (err != nil && !errors.Is(err, errPAMAccount)) {
			t.Errorf("checkShadow(%q, %d) = %v, refused want %v", tc.password, tc.expire, err, tc.refused)
		}
	}
}

func TestShellUsable(t *testing.T) {
	if err := shellUsable("/bin/sh"); err != nil {
		t.Fatalf("/bin/sh: %v", err)
	}
	for _, sh := range []string{"sh", "/nonexistent/sh", "/etc/hosts", "/"} {
		if err := shellUsable(sh); !errors.Is(err, errPAMAccount) {
			t.Errorf("%s: %v, want errPAMAccount", sh, err)
		}
	}
}
