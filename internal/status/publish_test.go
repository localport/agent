package status

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// readFrame reads one status frame from the launcher's end.
func readFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(r, frame); err != nil {
		t.Fatal(err)
	}
	return frame
}

// Publish retries a launcher it cannot reach, then sends the latest
// document and each newer one, and closes the connection when ctx ends.
func TestPublishRetriesThenSendsEachChange(t *testing.T) {
	b := NewBoard(7)
	ours, launcherEnd := net.Pipe()
	var opens atomic.Int32
	open := func(context.Context) (io.ReadWriteCloser, error) {
		if opens.Add(1) == 1 {
			return nil, launcher.ErrUnavailable
		}
		return ours, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Publish(ctx, b, open, t.Logf) }()

	_ = launcherEnd.SetDeadline(time.Now().Add(10 * time.Second))
	if doc, err := Decode(readFrame(t, launcherEnd)); err != nil || doc.PID != 7 || len(doc.Devices) != 0 {
		t.Fatalf("first document = %+v, %v", doc, err)
	}
	b.Set(Device{Identity: "d", State: StateRunning, Since: time.Now()})
	// A change signalled before the first write may repeat that document.
	for i := 0; ; i++ {
		doc, err := Decode(readFrame(t, launcherEnd))
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Devices) == 1 {
			break
		}
		if i == 2 {
			t.Fatalf("no document carries the change: %+v", doc)
		}
	}
	cancel()
	<-done
	if _, err := launcherEnd.Read(make([]byte, 1)); err == nil {
		t.Fatal("the publishing connection is still open after Publish returned")
	}
}

// A launcher that closes the connection (a restart) gets the document again
// on a new connection without any board change.
func TestPublishReconnectsWhenTheLauncherCloses(t *testing.T) {
	b := NewBoard(3)
	// Consume the board's initial change, so Publish writes one document and
	// then waits: only the close can make it reconnect.
	<-b.Changed()
	first, firstEnd := net.Pipe()
	second, secondEnd := net.Pipe()
	conns := make(chan io.ReadWriteCloser, 2)
	conns <- first
	conns <- second
	open := func(ctx context.Context) (io.ReadWriteCloser, error) {
		select {
		case c := <-conns:
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); Publish(ctx, b, open, t.Logf) }()
	defer func() { cancel(); <-done }()

	_ = firstEnd.SetDeadline(time.Now().Add(5 * time.Second))
	readFrame(t, firstEnd)
	_ = firstEnd.Close() // the launcher restarts
	_ = secondEnd.SetDeadline(time.Now().Add(5 * time.Second))
	if doc, err := Decode(readFrame(t, secondEnd)); err != nil || doc.PID != 3 {
		t.Fatalf("document after the launcher restart = %+v, %v", doc, err)
	}
}

// A board change never waits on a launcher that does not read.
func TestBoardNeverBlocksOnAStalledLauncher(t *testing.T) {
	b := NewBoard(1)
	ours, _ := net.Pipe() // nobody reads the launcher's end
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Publish(ctx, b, func(context.Context) (io.ReadWriteCloser, error) { return ours, nil }, t.Logf)
	set := make(chan struct{})
	go func() {
		for i := range 100 {
			b.Set(Device{Identity: "d", State: StateWaiting, Code: fmt.Sprintf("SE%03d", i), Since: time.Now()})
		}
		close(set)
	}()
	select {
	case <-set:
	case <-time.After(5 * time.Second):
		t.Fatal("Board.Set blocked on the publisher")
	}
}

func TestReadReportsNoDocument(t *testing.T) {
	prev := readStatus
	t.Cleanup(func() { readStatus = prev })
	readStatus = func(context.Context) ([]byte, error) { return nil, nil }
	if _, err := Read(context.Background()); !errors.Is(err, ErrNoDocument) {
		t.Fatalf("Read of an empty answer = %v, want ErrNoDocument", err)
	}
	readStatus = func(context.Context) ([]byte, error) { return []byte(`{"version":1,"pid":1,"devices":[],"x":1}`), nil }
	if _, err := Read(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read of an unknown field = %v, want ErrInvalid", err)
	}
}
