//go:build linux || darwin

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/localport/agent/internal/childproc"
)

// relayTestStage makes a re-executed test binary act as an agent child.
const relayTestStage = "LOCALPORT_RELAY_TEST_STAGE"

func TestMain(m *testing.M) {
	switch os.Getenv(relayTestStage) {
	case "report":
		// The child's session and what its descriptors 0-2 are.
		sid, _ := unix.Getsid(0)
		fmt.Printf("pid=%d sid=%d", os.Getpid(), sid)
		for fd := range 3 {
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				fmt.Printf(" fd%d=err", fd)
				continue
			}
			kind := "other"
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFCHR:
				kind = "chr"
			case unix.S_IFIFO:
				kind = "fifo"
			}
			fmt.Printf(" fd%d=%s:%d", fd, kind, uint64(st.Rdev))
		}
		fmt.Println(" END")
		os.Exit(0)
	case "hold":
		// Report READY, outlive the terminal's loss, then record whether a
		// SIGHUP arrived.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		fmt.Println("READY")
		time.Sleep(1500 * time.Millisecond)
		got := "hup=false"
		select {
		case <-hup:
			got = "hup=true"
		default:
		}
		_ = os.WriteFile(os.Getenv("LOCALPORT_RELAY_RESULT"), []byte(got), 0o600)
		os.Exit(0)
	}
	// Commands run in-process whatever the euid; the tests of the root
	// dispatch set agentChildRoot themselves.
	agentChildRoot = func() bool { return false }
	os.Exit(m.Run())
}

// testTerminal is a PTY standing in for root's terminal: the relay gets the
// slave as its std files, the test reads what reaches it from the master.
type testTerminal struct {
	master, slave *os.File
	mu            sync.Mutex
	out           bytes.Buffer
	readerDone    chan struct{}
}

func newTestTerminal(t *testing.T) *testTerminal {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	tt := &testTerminal{master: master, slave: slave, readerDone: make(chan struct{})}
	go func() {
		defer close(tt.readerDone)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			tt.mu.Lock()
			tt.out.Write(buf[:n])
			tt.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	return tt
}

func (tt *testTerminal) waitFor(t *testing.T, re *regexp.Regexp) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		tt.mu.Lock()
		m := re.FindStringSubmatch(tt.out.String())
		tt.mu.Unlock()
		if m != nil {
			return m
		}
		time.Sleep(10 * time.Millisecond)
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	t.Fatalf("no %v in %q", re, tt.out.String())
	return nil
}

func stageCmd(t *testing.T, stage string, env ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append([]string{relayTestStage + "=" + stage}, env...)
	return cmd
}

func runRelayedAsync(cmd *exec.Cmd, stdin io.Reader, stdout, stderr io.Writer, hangupIgnored bool) <-chan error {
	done := make(chan error, 1)
	go func() { done <- runRelayed(cmd, stdin, stdout, stderr, hangupIgnored) }()
	return done
}

func waitRelay(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runRelayed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runRelayed did not return")
	}
}

var reportPattern = regexp.MustCompile(`pid=(\d+) sid=(\d+) fd0=(\w+):(\d+) fd1=(\w+):(\d+) fd2=(\w+):(\d+) END`)

func ttyRdev(t *testing.T, f *os.File) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	return strconv.FormatUint(uint64(st.Rdev), 10)
}

// With root's descriptors 0-2 on a terminal, the child leads its own session
// and its descriptors 0-2 are a new PTY, never root's terminal.
func TestRunRelayedGivesTheChildItsOwnPTY(t *testing.T) {
	tt := newTestTerminal(t)
	waitRelay(t, runRelayedAsync(stageCmd(t, "report"), tt.slave, tt.slave, tt.slave, false))
	m := tt.waitFor(t, reportPattern)
	ownSid, _ := unix.Getsid(0)
	if m[1] != m[2] || m[2] == strconv.Itoa(ownSid) {
		t.Fatalf("child pid %s sid %s, test sid %d: want its own session", m[1], m[2], ownSid)
	}
	root := ttyRdev(t, tt.slave)
	for i := 3; i <= 7; i += 2 {
		if m[i] != "chr" || m[i+1] == root {
			t.Fatalf("child fd%d is %s:%s; root's terminal is %s", (i-3)/2, m[i], m[i+1], root)
		}
	}
	if m[4] != m[6] || m[6] != m[8] {
		t.Fatalf("child fds 0-2 on different terminals: %v", m[3:])
	}
}

// A stdin that is not a terminal stays a pipe; the terminal ones move to the
// PTY.
func TestRunRelayedKeepsANonTerminalStdin(t *testing.T) {
	tt := newTestTerminal(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_ = w.Close()
	waitRelay(t, runRelayedAsync(stageCmd(t, "report"), r, tt.slave, tt.slave, false))
	m := tt.waitFor(t, reportPattern)
	if m[3] != "fifo" || m[5] != "chr" || m[7] != "chr" || m[6] == ttyRdev(t, tt.slave) {
		t.Fatalf("child fds %v, want fd0 a pipe and fd1, fd2 a new PTY", m[3:])
	}
}

// Without any terminal the child keeps its pipes and still leads its own
// session.
func TestRunRelayedWithoutATerminal(t *testing.T) {
	var out bytes.Buffer
	waitRelay(t, runRelayedAsync(stageCmd(t, "report"), bytes.NewReader(nil), &out, io.Discard, false))
	m := reportPattern.FindStringSubmatch(out.String())
	ownSid, _ := unix.Getsid(0)
	if m == nil || m[1] != m[2] || m[2] == strconv.Itoa(ownSid) || m[3] != "fifo" || m[5] != "fifo" {
		t.Fatalf("child report %q, test sid %d: want its own session on pipes", out.String(), ownSid)
	}
}

// On terminal loss the child's group gets SIGHUP, unless root ignores
// SIGHUP: then the child runs on and its exit is returned.
func TestRunRelayedTerminalLoss(t *testing.T) {
	for _, tc := range []struct {
		hangupIgnored bool
		want          string
	}{
		{false, "hup=true"},
		{true, "hup=false"},
	} {
		t.Run(fmt.Sprintf("ignored=%v", tc.hangupIgnored), func(t *testing.T) {
			tt := newTestTerminal(t)
			result := filepath.Join(t.TempDir(), "result")
			done := runRelayedAsync(stageCmd(t, "hold", "LOCALPORT_RELAY_RESULT="+result), tt.slave, tt.slave, tt.slave, tc.hangupIgnored)
			tt.waitFor(t, regexp.MustCompile(`READY`))
			// A hangup of root's terminal: revoke (macOS, where closing the
			// master does not end its blocked Read), then close the master.
			if err := childproc.RevokeTTY(tt.slave.Name()); err != nil {
				t.Fatal(err)
			}
			_ = tt.master.Close()
			<-tt.readerDone
			waitRelay(t, done)
			got, err := os.ReadFile(result)
			if err != nil || string(got) != tc.want {
				t.Fatalf("child recorded %q, %v; want %s", got, err, tc.want)
			}
		})
	}
}
