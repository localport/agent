package recording

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testStart = time.Unix(1767225600, 0)

// parseEvent decodes one event line into its interval in milliseconds, code
// and data.
func parseEvent(t *testing.T, line []byte) (int64, string, string) {
	t.Helper()
	if !bytes.HasSuffix(line, []byte("\n")) || bytes.Count(line, []byte("\n")) != 1 {
		t.Fatalf("event line %q is not one newline-terminated line", line)
	}
	var ev []json.RawMessage
	if err := json.Unmarshal(line, &ev); err != nil || len(ev) != 3 {
		t.Fatalf("event line %q: %v", line, err)
	}
	ival := string(ev[0])
	dot := strings.IndexByte(ival, '.')
	if dot < 0 || len(ival)-dot-1 != 3 {
		t.Fatalf("interval %q is not millisecond precision", ival)
	}
	ms, err := strconv.ParseInt(ival[:dot]+ival[dot+1:], 10, 64)
	if err != nil {
		t.Fatalf("interval %q: %v", ival, err)
	}
	var code, data string
	if err := json.Unmarshal(ev[1], &code); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ev[2], &data); err != nil {
		t.Fatal(err)
	}
	return ms, code, data
}

// A files-log event is an "f" line whose data is the event's JSON as a
// string, timed like every other event.
func TestWriterFileEvent(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	event := `{"op":"read","path":"/srv/\"a\"","bytes":12,"result":"ok"}`
	ms, code, data := parseEvent(t, w.File(testStart.Add(1500*time.Millisecond), []byte(event)))
	if ms != 1500 || code != "f" || data != event {
		t.Fatalf("File = %d %q %q, want 1500 f %q", ms, code, data, event)
	}
	if ms, _, _ := parseEvent(t, w.Resize(testStart.Add(2*time.Second), 100, 30)); ms != 500 {
		t.Fatalf("the event after a file event is at +%d ms, want +500", ms)
	}
}

func TestWriterHeader(t *testing.T) {
	w := NewWriter(testStart, 120, 40)
	want := `{"version":3,"term":{"cols":120,"rows":40},"timestamp":1767225600}` + "\n"
	if got := string(w.Header()); got != want {
		t.Fatalf("Header = %q, want %q", got, want)
	}
}

func TestWriterIntervalErrorDiffusion(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	rng := rand.New(rand.NewPCG(1, 2))
	at := testStart
	var sum int64
	for i := range 10000 {
		at = at.Add(time.Duration(rng.IntN(1500)) * time.Microsecond)
		for _, l := range w.Output(at, []byte("x")) {
			ms, _, _ := parseEvent(t, l)
			sum += ms
		}
		real := at.Sub(testStart)
		if diff := real - time.Duration(sum)*time.Millisecond; diff > time.Millisecond || diff < -time.Millisecond {
			t.Fatalf("event %d: emitted %d ms, real %v", i, sum, real)
		}
	}
}

func TestWriterClockStepBack(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	l1 := w.Output(testStart.Add(2*time.Second), []byte("a"))[0]
	l2 := w.Output(testStart.Add(time.Second), []byte("b"))[0]
	l3 := w.Output(testStart.Add(3*time.Second), []byte("c"))[0]
	var got []int64
	for _, l := range [][]byte{l1, l2, l3} {
		ms, _, _ := parseEvent(t, l)
		got = append(got, ms)
	}
	if got[0] != 2000 || got[1] != 0 || got[2] != 1000 {
		t.Fatalf("intervals = %v, want [2000 0 1000]", got)
	}
}

func TestWriterInvalidUTF8(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	lines := w.Output(testStart, []byte("a\xffb\xc3\x28<&>\x00"))
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	_, code, data := parseEvent(t, lines[0])
	if code != "o" || data != "a�b�(<&>\x00" {
		t.Fatalf("event = %q %q", code, data)
	}
}

func TestWriterSplitRuneAcrossOutputs(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	euro := []byte("€") // e2 82 ac
	first := w.Output(testStart, append([]byte("a"), euro[:2]...))
	second := w.Output(testStart.Add(time.Millisecond), euro[2:])
	_, _, d1 := parseEvent(t, first[0])
	_, _, d2 := parseEvent(t, second[0])
	if d1 != "a" || d2 != "€" {
		t.Fatalf("data = %q, %q; want \"a\", \"€\"", d1, d2)
	}
	if got := w.Output(testStart, euro[:1]); got != nil {
		t.Fatalf("held byte produced lines %q", got)
	}
	lines := w.Exit(testStart.Add(time.Second), 0)
	if len(lines) != 2 {
		t.Fatalf("Exit gave %d lines, want 2", len(lines))
	}
	if _, code, data := parseEvent(t, lines[0]); code != "o" || data != "�" {
		t.Fatalf("flushed partial = %q %q", code, data)
	}
}

func TestWriterResizeAndExit(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	ms, code, data := parseEvent(t, w.Resize(testStart.Add(1500*time.Millisecond), 132, 50))
	if ms != 1500 || code != "r" || data != "132x50" {
		t.Fatalf("resize = %d %q %q", ms, code, data)
	}
	lines := w.Exit(testStart.Add(2*time.Second), 130)
	if len(lines) != 1 {
		t.Fatalf("Exit gave %d lines, want 1", len(lines))
	}
	ms, code, data = parseEvent(t, lines[0])
	if ms != 500 || code != "x" || data != "130" {
		t.Fatalf("exit = %d %q %q", ms, code, data)
	}
	if w.Flush(testStart) != nil {
		t.Fatal("Flush with nothing held returned a line")
	}
}

// A Windows status above MaxInt32 (0xC0000005) is recorded unsigned.
func TestWriterExitFullUint32(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	lines := w.Exit(testStart, 3221225477)
	if _, code, data := parseEvent(t, lines[0]); code != "x" || data != "3221225477" {
		t.Fatalf("exit = %q %q, want x 3221225477", code, data)
	}
}

func TestWriterSplitsLongOutput(t *testing.T) {
	w := NewWriter(testStart, 80, 24)
	// Control bytes expand sixfold in JSON, so 150 Ki of them needs many
	// events.
	data := bytes.Repeat([]byte("\x01é"), 150<<10)
	lines := w.Output(testStart.Add(time.Second), data)
	if len(lines) < 2 {
		t.Fatalf("got %d lines, want a split", len(lines))
	}
	var joined strings.Builder
	for i, l := range lines {
		if len(l) > MaxLine {
			t.Fatalf("line %d is %d bytes, over MaxLine", i, len(l))
		}
		ms, code, d := parseEvent(t, l)
		if code != "o" || (i == 0) != (ms == 1000) || (i > 0 && ms != 0) {
			t.Fatalf("line %d: interval %d code %q", i, ms, code)
		}
		joined.WriteString(d)
	}
	if joined.String() != string(data) {
		t.Fatal("split events do not rejoin to the output")
	}
}
