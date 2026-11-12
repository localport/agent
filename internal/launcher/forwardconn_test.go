package launcher

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// The forward server's stderr is logged quoted and bounded per session.
func TestFrameForwardTransportBoundsTheServersStderr(t *testing.T) {
	var ch bytes.Buffer
	line := bytes.Repeat([]byte("x"), 4<<10)
	if err := WriteFrame(&ch, Frame{Type: FrameStderr, Data: []byte("forged\nlauncher: started")}); err != nil {
		t.Fatal(err)
	}
	for range 2 * maxForwardLogBytes / len(line) {
		if err := WriteFrame(&ch, Frame{Type: FrameStderr, Data: line}); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteFrame(&ch, Frame{Type: FrameExit}); err != nil {
		t.Fatal(err)
	}
	var logged []string
	tr := newFrameForwardTransport(nopCloser{&ch}, func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) })
	if _, err := tr.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if logged[0] != `launcher: forward helper: "forged\nlauncher: started"` {
		t.Fatalf("first line %q", logged[0])
	}
	if n := 1 + maxForwardLogBytes/len(line); len(logged) > n+1 || !strings.Contains(logged[len(logged)-1], "dropped") {
		t.Fatalf("%d lines, last %q", len(logged), logged[len(logged)-1])
	}
}

type nopCloser struct{ io.ReadWriter }

func (nopCloser) Close() error { return nil }

// frameReader unwraps the data frames a piped helper relays.
type frameReader struct {
	fr   *FrameReader
	rest []byte
}

func (r *frameReader) Read(p []byte) (int, error) {
	for len(r.rest) == 0 {
		f, err := r.fr.ReadFrame()
		if err != nil {
			return 0, err
		}
		r.rest = f.Data
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

// TestFrameForwardTransportStreams runs the Windows path end to end: the
// client's messages ride data frames to a peer that, like the Windows
// forward server, answers a dial with ok and carries the forward as a
// credit-windowed stream (here an echo); 3 windows of bytes pass both ways.
func TestFrameForwardTransportStreams(t *testing.T) {
	agentEnd, helperEnd := net.Pipe()
	defer helperEnd.Close()
	var wmu sync.Mutex
	write := func(m FwdMsg) error {
		b, err := AppendForwardMsg(nil, m)
		if err != nil {
			return err
		}
		wmu.Lock()
		defer wmu.Unlock()
		return WriteFrame(helperEnd, Frame{Type: FrameData, Data: b})
	}
	mux := NewForwardMux(write)
	go func() {
		fr := NewForwardReader(&frameReader{fr: NewFrameReader(helperEnd)})
		for {
			m, err := fr.Read()
			if err != nil {
				mux.CloseAll()
				return
			}
			switch m.Type {
			case FwdDial:
				s, _ := mux.Open(m.ID)
				_ = write(FwdMsg{Type: FwdOK, ID: m.ID})
				go func() { _, _ = io.Copy(s, s); _ = s.Close() }()
			default:
				m.Data = bytes.Clone(m.Data)
				if err := mux.Deliver(m); err != nil {
					t.Errorf("deliver: %v", err)
					return
				}
			}
		}
	}()
	client := newForwardClient(newFrameForwardTransport(agentEnd, t.Logf), t.Logf)
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, FwdTCP, "localhost", 80, "")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("w"), 3*ForwardWindow)
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, %v", len(got), err)
	}
	_ = conn.Close()
	// The helper's exit frame ends the client.
	wmu.Lock()
	_ = WriteFrame(helperEnd, Frame{Type: FrameExit})
	wmu.Unlock()
	select {
	case <-client.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the exit frame did not end the client")
	}
	if _, err := client.Dial(ctx, FwdTCP, "localhost", 80, ""); err == nil {
		t.Fatal("a dial after the helper's end succeeded")
	}
}
