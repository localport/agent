//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// startPipe runs `sh -c command` on pipes as the test's user and returns the
// session and the agent's frame reader.
func startPipe(t *testing.T, command string) (*pipeSession, *launcher.FrameReader) {
	t.Helper()
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", command}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/"}
	p, err := startPipeSession(&frameWriter{w: helper}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.finish()
		p.Wait()
		agent.Close()
		helper.Close()
	})
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	return p, launcher.NewFrameReader(agent)
}

// The file server's event pipe is descriptor 3: a valid event is relayed as
// an event frame; an invalid one ends the session without its exit frame.
func TestPipeSessionRelaysOnlyValidEvents(t *testing.T) {
	agent, helper, err := launcher.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	defer helper.Close()
	// Frames: type 6, uint32 BE length, JSON (38 bytes valid, 14 invalid).
	script := `printf '\006\000\000\000\046{"op":"list","path":"/","result":"ok"}' >&3; sleep 0.2; ` +
		`printf '\006\000\000\000\016{"op":"chmod"}' >&3; sleep 30`
	plan := spawnPlan{path: "/bin/sh", args: []string{"sh", "-c", script}, env: []string{"PATH=/usr/bin:/bin"}, dir: "/", events: true}
	p, err := startPipeSession(&frameWriter{w: helper}, plan, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { p.finish(); p.Wait() }()
	_ = agent.SetDeadline(time.Now().Add(15 * time.Second))
	fr := launcher.NewFrameReader(agent)
	f, err := fr.ReadFrame()
	if err != nil || f.Type != launcher.FrameEvent || string(f.Data) != `{"op":"list","path":"/","result":"ok"}` {
		t.Fatalf("first frame %+v %q, %v", f, f.Data, err)
	}
	select {
	case <-p.endedC():
	case <-time.After(10 * time.Second):
		t.Fatal("an invalid event did not end the session")
	}
}

// readToExit collects stdout and stderr frames up to the exit frame.
func readToExit(t *testing.T, fr *launcher.FrameReader) (stdout, stderr string, code int32) {
	t.Helper()
	var out, errOut strings.Builder
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("no exit frame: %v; stdout %q stderr %q", err, out.String(), errOut.String())
		}
		switch f.Type {
		case launcher.FrameData:
			out.Write(f.Data)
		case launcher.FrameStderr:
			errOut.Write(f.Data)
		case launcher.FrameExit:
			return out.String(), errOut.String(), f.Code
		}
	}
}

// stdout and stderr travel in their own frames, and the exit status follows
// all output.
func TestPipeSessionSeparatesStderrAndExit(t *testing.T) {
	_, fr := startPipe(t, "echo out; echo err >&2; exit 4")
	stdout, stderr, code := readToExit(t, fr)
	if stdout != "out\n" || stderr != "err\n" || code != 4 {
		t.Fatalf("stdout %q stderr %q exit %d", stdout, stderr, code)
	}
}

// stdin data reaches the command and the eof frame closes its stdin.
func TestPipeSessionStdinAndEOF(t *testing.T) {
	p, fr := startPipe(t, "cat")
	if err := p.handle(launcher.Frame{Type: launcher.FrameData, Data: []byte("piped")}); err != nil {
		t.Fatal(err)
	}
	if err := p.handle(launcher.Frame{Type: launcher.FrameEOF}); err != nil {
		t.Fatal(err)
	}
	stdout, _, code := readToExit(t, fr)
	if stdout != "piped" || code != 0 {
		t.Fatalf("stdout %q exit %d", stdout, code)
	}
	if err := p.handle(launcher.Frame{Type: launcher.FrameResize, Cols: 80, Rows: 24}); err == nil {
		t.Fatal("a resize without a PTY was accepted")
	}
}

// The end path ends a command that ignores SIGHUP with SIGKILL to its group,
// so no frame follows and Wait returns.
func TestPipeSessionEndKillsTheCommand(t *testing.T) {
	p, _ := startPipe(t, "trap '' HUP; while :; do sleep 1; done")
	time.Sleep(100 * time.Millisecond)
	pid := p.cmd.Process.Pid
	p.finish()
	done := make(chan struct{})
	go func() { p.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(terminalKillDelay + 5*time.Second):
		t.Fatal("Wait did not return after the SIGKILL")
	}
	if proc, err := os.FindProcess(pid); err == nil && proc.Signal(nil) == nil {
		// Reaped by the waiter: a signal to the pid fails.
		t.Fatalf("command %d still runs", pid)
	}
}
