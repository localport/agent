package launcher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func roundTrip(t *testing.T, m FwdMsg) FwdMsg {
	t.Helper()
	b, err := AppendForwardMsg(nil, m)
	if err != nil {
		t.Fatalf("encode %+v: %v", m, err)
	}
	got, err := NewForwardReader(bytes.NewReader(b)).Read()
	if err != nil {
		t.Fatalf("decode %+v: %v", m, err)
	}
	return got
}

func TestForwardMsgRoundTrip(t *testing.T) {
	for _, m := range []FwdMsg{
		{Type: FwdDial, ID: 2, Network: FwdTCP, Host: "db.internal", Port: 5432},
		{Type: FwdDial, ID: 4, Network: FwdUnix, Path: "/run/docker.sock"},
		{Type: FwdListen, ID: 6, Network: FwdTCP, Port: 0},
		{Type: FwdListen, ID: 8, Network: FwdTCP, Port: 9000, IPv6: true},
		{Type: FwdListen, ID: 10, Network: FwdUnix, Path: "/tmp/s"},
		{Type: FwdClose, ID: 7},
		{Type: FwdOK, ID: 2},
		{Type: FwdOK, ID: 6, Port: 41000},
		{Type: FwdRefused, ID: 2, Code: FwdCodeConnectionRefused},
		{Type: FwdAccepted, ListenerID: 6, ID: 1, Host: "127.0.0.1", Port: 50000},
		{Type: FwdAccepted, ListenerID: 10, ID: 3},
		{Type: FwdData, ID: 1, Data: []byte("x")},
		{Type: FwdEOF, ID: 1},
		{Type: FwdWindow, ID: 1, N: ForwardWindow},
	} {
		got := roundTrip(t, m)
		if got.Type != m.Type || got.ID != m.ID || got.ListenerID != m.ListenerID || got.Network != m.Network ||
			got.Host != m.Host || got.Port != m.Port || got.IPv6 != m.IPv6 || got.Path != m.Path || got.Code != m.Code ||
			!bytes.Equal(got.Data, m.Data) || got.N != m.N {
			t.Errorf("round trip %+v = %+v", m, got)
		}
	}
}

// TestForwardMsgRefusesOutOfBounds checks every field bound on both sides:
// the encoder refuses the message and the decoder refuses its bytes.
func TestForwardMsgRefusesOutOfBounds(t *testing.T) {
	for name, m := range map[string]FwdMsg{
		"dial odd id":          {Type: FwdDial, ID: 3, Network: FwdTCP, Host: "h", Port: 1},
		"dial empty host":      {Type: FwdDial, ID: 2, Network: FwdTCP, Port: 1},
		"dial host too long":   {Type: FwdDial, ID: 2, Network: FwdTCP, Host: strings.Repeat("h", MaxForwardHost+1), Port: 1},
		"dial host NUL":        {Type: FwdDial, ID: 2, Network: FwdTCP, Host: "a\x00b", Port: 1},
		"dial port 0":          {Type: FwdDial, ID: 2, Network: FwdTCP, Host: "h"},
		"dial relative path":   {Type: FwdDial, ID: 2, Network: FwdUnix, Path: "run/s"},
		"dial path too long":   {Type: FwdDial, ID: 2, Network: FwdUnix, Path: "/" + strings.Repeat("p", MaxForwardPath)},
		"dial path NUL":        {Type: FwdDial, ID: 2, Network: FwdUnix, Path: "/a\x00"},
		"dial bad network":     {Type: FwdDial, ID: 2, Network: 9, Host: "h", Port: 1},
		"listen odd id":        {Type: FwdListen, ID: 1, Network: FwdTCP},
		"listen empty path":    {Type: FwdListen, ID: 2, Network: FwdUnix},
		"ok odd id":            {Type: FwdOK, ID: 1},
		"refused unknown code": {Type: FwdRefused, ID: 2, Code: 99},
		"refused odd id":       {Type: FwdRefused, ID: 1, Code: FwdCodeLimit},
		"accepted even id":     {Type: FwdAccepted, ListenerID: 2, ID: 4},
		"accepted odd lid":     {Type: FwdAccepted, ListenerID: 3, ID: 5},
		"accepted host long":   {Type: FwdAccepted, ListenerID: 2, ID: 5, Host: strings.Repeat("h", MaxForwardHost+1)},
		"data empty":           {Type: FwdData, ID: 1},
		"data too long":        {Type: FwdData, ID: 1, Data: make([]byte, MaxForwardData+1)},
		"window zero":          {Type: FwdWindow, ID: 1},
		"window past credit":   {Type: FwdWindow, ID: 1, N: ForwardWindow + 1},
		"unknown type":         {Type: 42, ID: 2},
	} {
		if _, err := AppendForwardMsg(nil, m); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	raw := func(typ byte, payload ...byte) []byte {
		b := []byte{typ, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
		return append(b, payload...)
	}
	for name, b := range map[string][]byte{
		"short id":              raw(FwdClose, 0, 0, 1),
		"close trailing byte":   raw(FwdClose, 0, 0, 0, 1, 9),
		"ok short port":         raw(FwdOK, 0, 0, 0, 2, 1),
		"listen bad family":     raw(FwdListen, 0, 0, 0, 2, FwdTCP, 0, 80, 5),
		"listen trailing":       raw(FwdListen, 0, 0, 0, 2, FwdTCP, 0, 80, 4, 4),
		"refused no code":       raw(FwdRefused, 0, 0, 0, 2),
		"window short":          raw(FwdWindow, 0, 0, 0, 1, 0, 1),
		"payload over the max":  {FwdData, 0, 1, 0, 5},
		"truncated payload":     {FwdClose, 0, 0, 0, 4, 0, 0},
		"truncated header":      {FwdClose, 0, 0},
		"accepted short header": raw(FwdAccepted, 0, 0, 0, 2, 0, 0, 0),
	} {
		if _, err := NewForwardReader(bytes.NewReader(b)).Read(); err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: decoded (%v)", name, err)
		}
	}
	if _, err := NewForwardReader(bytes.NewReader(nil)).Read(); !errors.Is(err, io.EOF) {
		t.Errorf("empty stream: %v, want io.EOF", err)
	}
}

// FuzzForwardReader checks that any decoded message re-encodes to the same
// bytes, so the decoder accepts nothing the encoder's bounds refuse.
func FuzzForwardReader(f *testing.F) {
	for _, m := range []FwdMsg{
		{Type: FwdDial, ID: 2, Network: FwdTCP, Host: "h", Port: 22},
		{Type: FwdListen, ID: 2, Network: FwdUnix, Path: "/s"},
		{Type: FwdAccepted, ListenerID: 2, ID: 1, Host: "::1", Port: 1},
		{Type: FwdWindow, ID: 1, N: 1},
	} {
		b, _ := AppendForwardMsg(nil, m)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewForwardReader(bytes.NewReader(b))
		consumed := 0
		for {
			m, err := r.Read()
			if err != nil {
				return
			}
			enc, err := AppendForwardMsg(nil, m)
			if err != nil {
				t.Fatalf("decoded %+v does not encode: %v", m, err)
			}
			if !bytes.Equal(enc, b[consumed:consumed+len(enc)]) {
				t.Fatalf("decoded %+v re-encodes differently", m)
			}
			consumed += len(enc)
		}
	})
}

// muxPair connects two muxes back to back through goroutine-free delivery.
func muxPair(t *testing.T) (a, b *ForwardMux) {
	t.Helper()
	var mu sync.Mutex
	var deliverA, deliverB func(FwdMsg) error
	a = NewForwardMux(func(m FwdMsg) error {
		mu.Lock()
		d := deliverB
		mu.Unlock()
		m.Data = bytes.Clone(m.Data)
		return d(m)
	})
	b = NewForwardMux(func(m FwdMsg) error {
		mu.Lock()
		d := deliverA
		mu.Unlock()
		m.Data = bytes.Clone(m.Data)
		return d(m)
	})
	deliverA, deliverB = a.Deliver, b.Deliver
	return a, b
}

// TestForwardMuxCreditWindow checks that a sender stops at ForwardWindow
// unacknowledged bytes and resumes as the reader consumes them.
func TestForwardMuxCreditWindow(t *testing.T) {
	a, b := muxPair(t)
	sa, err := a.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := b.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("z"), 3*ForwardWindow)
	wrote := make(chan int, 1)
	go func() {
		n, _ := sa.Write(payload)
		wrote <- n
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		sb.mu.Lock()
		buffered := len(sb.buf)
		sb.mu.Unlock()
		if buffered == ForwardWindow {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("receiver buffered %d bytes, want the window %d", buffered, ForwardWindow)
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case n := <-wrote:
		t.Fatalf("the writer finished (%d bytes) past the window", n)
	case <-time.After(50 * time.Millisecond):
	}
	got, err := io.ReadAll(io.LimitReader(sb, int64(len(payload))))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, %v", len(got), err)
	}
	if n := <-wrote; n != len(payload) {
		t.Fatalf("wrote %d", n)
	}
	// A peer that sends past the window breaks the protocol.
	if err := b.Deliver(FwdMsg{Type: FwdData, ID: 1, Data: make([]byte, MaxForwardData)}); err != nil {
		t.Fatal(err)
	}
	if err := b.Deliver(FwdMsg{Type: FwdData, ID: 1, Data: make([]byte, MaxForwardData)}); err != nil {
		t.Fatal(err)
	}
	if err := b.Deliver(FwdMsg{Type: FwdData, ID: 1, Data: []byte{1}}); err == nil {
		t.Fatal("data past the window was accepted")
	}
	// A window past the grant breaks it too.
	if err := a.Deliver(FwdMsg{Type: FwdWindow, ID: 1, N: ForwardWindow}); err == nil {
		t.Fatal("a window past the grant was accepted")
	}
}

// The stream count is the live streams: a close from either side leaves it
// at once, so a dial after that close is not refused for it.
func TestForwardMuxLenCountsOnlyLiveStreams(t *testing.T) {
	m := NewForwardMux(func(FwdMsg) error { return nil })
	for id := range uint32(3) {
		if _, err := m.Open(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Deliver(FwdMsg{Type: FwdClose, ID: 0}); err != nil {
		t.Fatal(err)
	}
	if got := m.Len(); got != 2 {
		t.Fatalf("Len after the peer's close = %d, want 2", got)
	}
	s := m.streams[1]
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("Len after a local close = %d, want 1", got)
	}
}

// TestForwardMuxPeerClose checks that bytes received before the peer's close
// stay readable and the read then fails, and that a closed stream's writer
// wakes.
func TestForwardMuxPeerClose(t *testing.T) {
	a, b := muxPair(t)
	sa, _ := a.Open(1)
	sb, _ := b.Open(1)
	if _, err := sa.Write([]byte("last")); err != nil {
		t.Fatal(err)
	}
	if err := sa.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := sb.Read(buf)
	if err != nil || string(buf[:n]) != "last" {
		t.Fatalf("read %q, %v", buf[:n], err)
	}
	if _, err := sb.Read(buf); err == nil {
		t.Fatal("read after the peer's close succeeded")
	}
	if _, err := sb.Write([]byte("x")); err == nil {
		t.Fatal("write after the peer's close succeeded")
	}
	if b.Len() != 0 || a.Len() != 0 {
		t.Fatalf("streams left: %d, %d", a.Len(), b.Len())
	}
}
