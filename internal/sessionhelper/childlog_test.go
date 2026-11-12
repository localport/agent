//go:build cgo && (linux || darwin)

package sessionhelper

import (
	"fmt"
	"strings"
	"testing"
)

// PAM text keeps tab and newline; every other control byte, C1 control and
// invalid UTF-8 becomes U+FFFD, so a module cannot drive the client's
// terminal; collection stops at maxPAMMessageBytes.
func TestPAMMessagesSanitize(t *testing.T) {
	m := &pamMessages{}
	m.add("Last login:\tnow\n\x1b[2J\x07\xc2\x9b31m\xff")
	if got, want := m.messages()[0], "Last login:\tnow\n�[2J��31m�"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	big := &pamMessages{}
	for range 20 {
		big.add(strings.Repeat("x", 1<<10))
	}
	if len(big.list) != maxPAMMessageBytes>>10 {
		t.Fatalf("kept %d messages", len(big.list))
	}
	var nilMsgs *pamMessages
	nilMsgs.add("x")
	if nilMsgs.messages() != nil {
		t.Fatal("a nil collector returned messages")
	}
}

func collectChildLog(input string) []string {
	var lines []string
	relayChildLog(strings.NewReader(input), "p:", func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	})
	return lines
}

// Each line is quoted, so a login cannot forge a log line with a newline or
// control bytes.
func TestRelayChildLogQuotesLines(t *testing.T) {
	got := collectChildLog("dial failed\nlauncher: session x started\x1b[2K\nlast")
	want := []string{`p: "dial failed"`, `p: "launcher: session x started\x1b[2K"`, `p: "last"`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

// A line over maxChildLogLine is cut and its rest dropped; the next line is
// relayed whole.
func TestRelayChildLogBoundsALine(t *testing.T) {
	got := collectChildLog(strings.Repeat("a", 3*maxChildLogLine) + "\nnext\n")
	if len(got) != 2 || len(got[0]) != len(`p: ""`)+maxChildLogLine || got[1] != `p: "next"` {
		t.Fatalf("got %d lines, first %d bytes: %q", len(got), len(got[0]), got[len(got)-1])
	}
}

// Past maxChildLogBytes one notice is logged and the rest is drained unlogged.
func TestRelayChildLogBoundsTheTotal(t *testing.T) {
	line := strings.Repeat("b", 99) + "\n"
	got := collectChildLog(strings.Repeat(line, 2*maxChildLogBytes/len(line)))
	if n := maxChildLogBytes / len(line); len(got) != n+1 {
		t.Fatalf("%d lines, want %d and the notice", len(got), n)
	}
	if last := got[len(got)-1]; !strings.Contains(last, "dropped") {
		t.Fatalf("last line %q, want the drop notice", last)
	}
}
