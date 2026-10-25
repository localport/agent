package session

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseTerminalStart(t *testing.T) {
	for _, tc := range []struct {
		body string
		want *terminalStart // nil: protocol_error
	}{
		{`{"cols":80,"rows":24}`, &terminalStart{terminalSize{80, 24}, "xterm-256color"}},
		{`{"cols":1,"rows":1000,"term":"vt100"}`, &terminalStart{terminalSize{1, 1000}, "vt100"}},
		{`{"cols":1000,"rows":1,"term":"screen.xterm-256color+x"}`, &terminalStart{terminalSize{1000, 1}, "screen.xterm-256color+x"}},
		{`{"cols":80,"rows":24,"term":null}`, &terminalStart{terminalSize{80, 24}, "xterm-256color"}},
		{`{"cols":80,"rows":24,"term":"` + strings.Repeat("a", 32) + `"}`, &terminalStart{terminalSize{80, 24}, strings.Repeat("a", 32)}},
		{`{"cols":80,"rows":24,"term":"` + strings.Repeat("a", 33) + `"}`, nil},
		{`{"cols":80,"rows":24,"term":""}`, nil},
		{`{"cols":80,"rows":24,"term":"xterm 256"}`, nil},
		{`{"cols":80,"rows":24,"term":"xterm\n"}`, nil},
		{`{"cols":80,"rows":24,"term":"x/y"}`, nil},
		{`{"cols":0,"rows":24}`, nil},
		{`{"cols":1001,"rows":24}`, nil},
		{`{"cols":80,"rows":0}`, nil},
		{`{"cols":80,"rows":-1}`, nil},
		{`{"cols":80,"rows":1001}`, nil},
		{`{"cols":80.5,"rows":24}`, nil},
		{`{"cols":"80","rows":24}`, nil},
		{`{"rows":24}`, nil},
		{`{"cols":80,"rows":24,"login":"root"}`, nil},
		{`{"cols":80,"rows":24} {}`, nil},
		{`{}`, nil},
		{``, nil},
		{`[]`, nil},
	} {
		t.Run(tc.body, func(t *testing.T) {
			got, err := parseTerminalStart([]byte(tc.body))
			if tc.want == nil {
				if codeOf(err) != CodeProtocolError {
					t.Fatalf("got %+v, %v; want protocol_error", got, err)
				}
				return
			}
			if err != nil || got != *tc.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, *tc.want)
			}
		})
	}
}

func TestDecodeTerminalInput(t *testing.T) {
	for _, tc := range []struct {
		typ    MessageType
		body   string
		resize *terminalSize
		ok     bool
	}{
		{TypeData, "keys", nil, true},
		{TypeResize, `{"cols":120,"rows":40}`, &terminalSize{120, 40}, true},
		{TypeResize, `{"cols":120,"rows":1001}`, nil, false},
		{TypeResize, `{"cols":0,"rows":40}`, nil, false},
		{TypeResize, `{"cols":120,"rows":40,"term":"vt100"}`, nil, false},
		{TypeResize, `not json`, nil, false},
		{TypeExit, `{"code":0}`, nil, false},
		{TypeKindBase + 2, ``, nil, false},
		{0xff, ``, nil, false},
		{TypeStart, `{}`, nil, false},
	} {
		t.Run(strconv.Itoa(int(tc.typ))+" "+tc.body, func(t *testing.T) {
			in, err := decodeTerminalInput(Message{Type: tc.typ, Body: []byte(tc.body)})
			if !tc.ok {
				if codeOf(err) != CodeProtocolError {
					t.Fatalf("got %+v, %v; want protocol_error", in, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.resize != nil:
				if in.resize == nil || *in.resize != *tc.resize || in.data != nil {
					t.Fatalf("got %+v, want resize %+v", in, *tc.resize)
				}
			case string(in.data) != tc.body || in.resize != nil:
				t.Fatalf("got %+v, want data %q", in, tc.body)
			}
		})
	}
}

// One data record carries the largest PTY output chunk.
func TestTerminalOutputFitsOneRecord(t *testing.T) {
	if maxTerminalOutput > MaxBody {
		t.Fatalf("maxTerminalOutput %d exceeds MaxBody %d", maxTerminalOutput, MaxBody)
	}
}

func TestExitBody(t *testing.T) {
	for code, want := range map[int]string{0: `{"code":0}`, 127: `{"code":127}`, 129: `{"code":129}`} {
		if got := string(exitBody(code)); got != want {
			t.Errorf("exitBody(%d) = %s, want %s", code, got, want)
		}
	}
}
