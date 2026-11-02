//go:build windows

package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testPipeName(t *testing.T) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return `\\.\pipe\localport-test-` + hex.EncodeToString(b[:])
}

func currentSID(t *testing.T) *windows.SID {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := u.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// listen serves name owned by this test's user, the stand-in for SYSTEM.
func listen(t *testing.T, name string, me *windows.SID) *PipeListener {
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	l := &PipeListener{name: name, sddl: "O:" + me.String() + "D:P(A;;GA;;;" + me.String() + ")", first: true, stop: stop}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// The server reads the client's token; the client checks the pipe's owner.
func TestPipeClientAndOwnerChecks(t *testing.T) {
	me := currentSID(t)
	name := testPipeName(t)
	l := listen(t, name, me)
	accepted := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		sid, err := pipeClientSID(conn)
		if err == nil && !sid.Equals(me) {
			err = errors.New("client SID " + sid.String())
		}
		accepted <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The first dial waits until Accept created the instance.
	var conn interface{ Close() error }
	for {
		c, err := dialPipe(ctx, name, me)
		if err == nil {
			conn = c
			break
		}
		if ctx.Err() != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer conn.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}

	// A pipe owned by anyone but the expected server is refused.
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	for {
		_, err := dialPipe(ctx, name, system)
		if errors.Is(err, errPipeOwner) {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("dial expecting SYSTEM = %v, want errPipeOwner", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The session channel pipe is owned by its creator, opens once, and refuses
// a name outside the session pattern.
func TestSessionChannel(t *testing.T) {
	ours, pipe, err := NewSessionChannel()
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	if !pipePattern.MatchString(pipe) {
		t.Fatalf("pipe %q does not match the session pattern", pipe)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	theirs, err := OpenSessionChannel(ctx, pipe, currentSID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer theirs.Close()
	if _, err := theirs.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := ours.Read(buf); err != nil || buf[0] != 'x' {
		t.Fatalf("read %q, %v", buf, err)
	}
	if _, err := OpenSessionChannel(ctx, `\\.\pipe\other`, currentSID(t)); err == nil {
		t.Fatal("a name outside the session pattern must be refused")
	}
	// A second creator of the same name fails: the name is the first one's.
	if _, err := createPipeInstance(pipe, "D:P(A;;GA;;;WD)", true, 1); err == nil {
		t.Fatal("a second first instance of the session pipe must fail")
	}
}
