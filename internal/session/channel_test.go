package session

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// recorder keeps each Write as one record.
type recorder struct{ records [][]byte }

func (r *recorder) Write(p []byte) (int, error) {
	r.records = append(r.records, bytes.Clone(p))
	return len(p), nil
}

func (r *recorder) Read([]byte) (int, error) { return 0, io.EOF }

func testKeys() Keys {
	return Keys{C2A: fixed("c2a"), A2C: fixed("a2c")}
}

// sealRecords writes msgs from the client and returns each sealed record.
func sealRecords(t *testing.T, msgs ...[]byte) [][]byte {
	t.Helper()
	rec := &recorder{}
	ch, err := testKeys().ClientChannel(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if err := ch.WriteMessage(TypeData, m); err != nil {
			t.Fatal(err)
		}
	}
	return rec.records
}

// agentReading returns an agent channel that reads the given bytes.
func agentReading(t *testing.T, wire ...[]byte) *Channel {
	t.Helper()
	rw := struct {
		io.Reader
		io.Writer
	}{bytes.NewReader(bytes.Join(wire, nil)), io.Discard}
	ch, err := testKeys().AgentChannel(rw)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestChannelRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{0xab}, MaxBody)
	var wire bytes.Buffer
	client, err := testKeys().ClientChannel(&wire)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := testKeys().AgentChannel(&wire)
	if err != nil {
		t.Fatal(err)
	}
	sent := []Message{
		{Type: TypeStart, Body: []byte(`{"cols":80}`)},
		{Type: TypeData, Body: []byte("hello")},
		{Type: TypeData, Body: big},
		{Type: TypeActivity, Body: []byte{}},
		{Type: TypeKindBase, Body: []byte{1, 2}},
		{Type: 0xff, Body: []byte{}},
	}
	for _, m := range sent {
		if err := client.WriteMessage(m.Type, m.Body); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.WriteClose("idle"); err != nil {
		t.Fatal(err)
	}
	for _, want := range sent {
		got, err := agent.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("got type %#x body %d bytes; want %#x %d bytes", got.Type, len(got.Body), want.Type, len(want.Body))
		}
	}
	got, err := agent.ReadMessage()
	if err != nil || got.Type != TypeClose || got.Reason != "idle" {
		t.Fatalf("close = %+v, %v", got, err)
	}
	// The agent's own sends use the other key and counter.
	if err := agent.WriteMessage(TypeData, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	if got, err := client.ReadMessage(); err != nil || string(got.Body) != "reply" {
		t.Fatalf("reply = %+v, %v", got, err)
	}
}

func TestChannelRefusesOutOfOrder(t *testing.T) {
	r := sealRecords(t, []byte("zero"), []byte("one"))
	cases := []struct {
		name string
		wire [][]byte
	}{
		{"gap", [][]byte{r[1]}},
		{"reorder", [][]byte{r[1], r[0]}},
		{"replay", [][]byte{r[0], r[0]}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := agentReading(t, tc.wire...)
			var err error
			for range tc.wire {
				if _, err = ch.ReadMessage(); err != nil {
					break
				}
			}
			if codeOf(err) != CodeProtocolError {
				t.Fatalf("err = %v; want %s", err, CodeProtocolError)
			}
		})
	}
}

func TestChannelAuthFailureIsSticky(t *testing.T) {
	r := sealRecords(t, []byte("zero"), []byte("one"))
	flipped := bytes.Clone(r[0])
	flipped[len(flipped)-1] ^= 1
	// r[1] is sealed under the counter the reader moves to after the failure.
	ch := agentReading(t, flipped, r[1])
	if _, err := ch.ReadMessage(); codeOf(err) != CodeProtocolError {
		t.Fatalf("flipped record: %v", err)
	}
	if _, err := ch.ReadMessage(); codeOf(err) != CodeProtocolError {
		t.Fatalf("valid record after a failure was read: %v", err)
	}
}

func TestChannelRefusesOversizeRecord(t *testing.T) {
	header := binary.BigEndian.AppendUint32(nil, maxSealed+1)
	rd := bytes.NewReader(append(header, make([]byte, maxSealed+1)...))
	ch, err := testKeys().AgentChannel(struct {
		io.Reader
		io.Writer
	}{rd, io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadMessage(); codeOf(err) != CodeProtocolError {
		t.Fatalf("err = %v; want %s", err, CodeProtocolError)
	}
	if rd.Len() != maxSealed+1 {
		t.Fatalf("read %d body bytes of an oversize record", maxSealed+1-rd.Len())
	}

	client, err := testKeys().ClientChannel(&recorder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.WriteMessage(TypeData, make([]byte, MaxBody+1)); codeOf(err) != CodeProtocolError {
		t.Fatalf("oversize write = %v", err)
	}
}

func TestChannelTruncation(t *testing.T) {
	r := sealRecords(t, []byte("zero"))
	cases := []struct {
		name string
		wire []byte
	}{
		{"end before any record", nil},
		{"end inside the header", r[0][:2]},
		{"end inside the body", r[0][:len(r[0])-1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := agentReading(t, tc.wire).ReadMessage(); codeOf(err) != CodeTruncated {
				t.Fatalf("err = %v; want %s", err, CodeTruncated)
			}
		})
	}
	ch := agentReading(t, r[0])
	if _, err := ch.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadMessage(); codeOf(err) != CodeTruncated {
		t.Fatalf("end after a data record without close = %v; want %s", err, CodeTruncated)
	}
}

// sealRaw seals plaintext as the client's record number seq, bypassing the
// envelope.
func sealRaw(t *testing.T, seq uint64, plain []byte) []byte {
	t.Helper()
	aead, err := chacha20poly1305.New(testKeys().C2A)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], seq)
	sealed := aead.Seal(nil, nonce, plain, nil)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(sealed))), sealed...)
}

func TestReadMessageRefusesBadEnvelope(t *testing.T) {
	cases := []struct {
		name  string
		plain []byte
	}{
		{"empty record", nil},
		{"unassigned type 0x04", []byte{0x04}},
		{"unassigned type 0x0f", []byte{0x0f, 1}},
		{"close without reason", []byte{0x00}},
		{"close with empty reason", append([]byte{0x00}, `{"reason":""}`...)},
		{"activity with a body", []byte{0x03, 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := agentReading(t, sealRaw(t, 0, tc.plain)).ReadMessage(); codeOf(err) != CodeProtocolError {
				t.Fatalf("err = %v; want %s", err, CodeProtocolError)
			}
		})
	}
}

// TestChannelReusesBuffers checks a write and a read allocate nothing: each
// direction seals and opens in its one buffer.
func TestChannelReusesBuffers(t *testing.T) {
	var wire bytes.Buffer
	wire.Grow(2 * (recordHeader + maxSealed))
	client, err := testKeys().ClientChannel(&wire)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := testKeys().AgentChannel(&wire)
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, MaxBody)
	allocs := testing.AllocsPerRun(50, func() {
		if err := client.WriteMessage(TypeData, body); err != nil {
			t.Fatal(err)
		}
		if _, err := agent.ReadMessage(); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("%v allocations per record", allocs)
	}
}

// TestChannelConcurrentWriters runs writers in parallel with a reader; each
// record must arrive whole and in a counter order the reader accepts.
func TestChannelConcurrentWriters(t *testing.T) {
	agentEnd, clientEnd := net.Pipe()
	defer agentEnd.Close()
	defer clientEnd.Close()
	client, err := testKeys().ClientChannel(clientEnd)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := testKeys().AgentChannel(agentEnd)
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 4, 50
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				if err := client.WriteMessage(TypeData, fmt.Appendf(nil, "%d-%d", w, i)); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for range writers * each {
		if _, err := agent.ReadMessage(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

// Once close is sealed, by WriteClose or WriteMessage(TypeClose), every later
// write is refused ErrChannelClosed and nothing more is written.
func TestChannelRefusesWritesAfterClose(t *testing.T) {
	for name, closeWith := range map[string]func(*Channel) error{
		"WriteClose":   func(c *Channel) error { return c.WriteClose("done") },
		"WriteMessage": func(c *Channel) error { return c.WriteMessage(TypeClose, []byte(`{"reason":"done"}`)) },
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}
			ch, err := testKeys().AgentChannel(rec)
			if err != nil {
				t.Fatal(err)
			}
			if err := closeWith(ch); err != nil {
				t.Fatal(err)
			}
			if err := ch.WriteMessage(TypeData, []byte("late")); !errors.Is(err, ErrChannelClosed) {
				t.Fatalf("data after close = %v, want ErrChannelClosed", err)
			}
			if err := ch.WriteClose("again"); !errors.Is(err, ErrChannelClosed) {
				t.Fatalf("close after close = %v, want ErrChannelClosed", err)
			}
			if len(rec.records) != 1 {
				t.Fatalf("%d records written, want only the close", len(rec.records))
			}
		})
	}
}
