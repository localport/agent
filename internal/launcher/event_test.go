package launcher

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Each operation carries its own fields: a path and a result always (exec
// only a command), a target for rename, symlink and link, bytes for read and
// write; anything else, an unknown operation or an out-of-bounds field is
// refused.
func TestFileEventValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   FileEvent
		ok   bool
	}{
		{"exec", FileEvent{Op: OpExec, Command: "uname -a"}, true},
		{"login shell on pipes", FileEvent{Op: OpExec}, true},
		{"read", FileEvent{Op: OpRead, Path: "/srv/a", Bytes: 4096, Result: ResultOK}, true},
		{"write failed", FileEvent{Op: OpWrite, Path: "/srv/a", Result: "permission_denied"}, true},
		{"rename", FileEvent{Op: OpRename, Path: "/a", Target: "/b", Result: ResultOK}, true},
		{"list", FileEvent{Op: OpList, Path: "/", Result: ResultOK}, true},
		{"exec with a path", FileEvent{Op: OpExec, Command: "id", Path: "/x"}, false},
		{"exec with a result", FileEvent{Op: OpExec, Command: "id", Result: ResultOK}, false},
		{"read without a result", FileEvent{Op: OpRead, Path: "/a"}, false},
		{"read without a path", FileEvent{Op: OpRead, Result: ResultOK}, false},
		{"read with a target", FileEvent{Op: OpRead, Path: "/a", Target: "/b", Result: ResultOK}, false},
		{"rename without a target", FileEvent{Op: OpRename, Path: "/a", Result: ResultOK}, false},
		{"mkdir with bytes", FileEvent{Op: OpMkdir, Path: "/a", Bytes: 1, Result: ResultOK}, false},
		{"sftp op with a command", FileEvent{Op: OpRemove, Path: "/a", Command: "rm", Result: ResultOK}, false},
		{"negative bytes", FileEvent{Op: OpWrite, Path: "/a", Bytes: -1, Result: ResultOK}, false},
		{"unknown op", FileEvent{Op: "chmod", Path: "/a", Result: ResultOK}, false},
		{"result not a code", FileEvent{Op: OpRead, Path: "/a", Result: "Permission Denied"}, false},
		{"path too long", FileEvent{Op: OpRead, Path: "/" + strings.Repeat("a", maxEventPath), Result: ResultOK}, false},
		{"path not UTF-8", FileEvent{Op: OpRead, Path: "/\xff", Result: ResultOK}, false},
		{"command too long", FileEvent{Op: OpExec, Command: strings.Repeat("x", MaxCommand+1)}, false},
	} {
		if err := tc.ev.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: Validate = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// An event frame round-trips its JSON; an empty or oversized one is refused
// on both ends; ParseFileEvent refuses unknown fields and invalid events.
func TestEventFrame(t *testing.T) {
	ev := FileEvent{Op: OpRename, Path: "/a", Target: "/b", Result: ResultOK}
	payload, err := ev.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Type: FrameEvent, Data: payload}); err != nil {
		t.Fatal(err)
	}
	f, err := NewFrameReader(&buf).ReadFrame()
	if err != nil || f.Type != FrameEvent {
		t.Fatalf("ReadFrame = %+v, %v", f, err)
	}
	if got, err := ParseFileEvent(f.Data); err != nil || got != ev {
		t.Fatalf("ParseFileEvent = %+v, %v", got, err)
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxFrameEvent+1)} {
		if err := WriteFrame(&buf, Frame{Type: FrameEvent, Data: data}); err == nil {
			t.Errorf("WriteFrame of a %d-byte event accepted", len(data))
		}
	}
	oversized := binary.BigEndian.AppendUint32([]byte{FrameEvent}, MaxFrameEvent+1)
	oversized = append(oversized, bytes.Repeat([]byte{'x'}, MaxFrameEvent+1)...)
	if _, err := NewFrameReader(bytes.NewReader(oversized)).ReadFrame(); err == nil {
		t.Error("ReadFrame of an oversized event accepted")
	}
	for _, p := range []string{`{"op":"read","path":"/a","result":"ok","mode":1}`, `{"op":"read","path":"/a"}`, `not json`} {
		if _, err := ParseFileEvent([]byte(p)); err == nil {
			t.Errorf("ParseFileEvent(%s) accepted", p)
		}
	}
}
