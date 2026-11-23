package launcher

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// fullHome is the longest valid Started.Home in its worst escaped form:
// every byte escapes to six.
var fullHome = strings.Repeat("<", (MaxFilesHome-2)/6)

// Messages made of the characters JSON escapes most (`<` becomes \u003c) are
// cut until the largest reply on both hops still encodes.
func TestFitMessagesBoundsTheEncodedReply(t *testing.T) {
	worst := strings.Repeat("<\"\n", MaxMessage)
	msgs := FitMessages([]string{worst, worst, worst})
	if len(msgs) != 1 || len(msgs[0]) == 0 || len(msgs[0]) >= len(worst) {
		t.Fatalf("fitted to %d messages, first %d bytes", len(msgs), len(msgs[0]))
	}
	for _, v := range []any{
		HelperReply{Refused: CodeAccountUnavailable, Messages: msgs},
		HelperReply{Started: true, Messages: msgs, Confined: true, Home: fullHome, WholeDisk: true},
		Response{Started: &Started{SessionID: newSessionID(), Confined: true, Home: fullHome, WholeDisk: true}, Messages: msgs, FullDiskAccess: FullDiskAccessGranted},
		Response{Refused: &Refused{Code: CodeAccountUnavailable}, Messages: msgs},
	} {
		if _, err := encode(v); err != nil {
			t.Fatalf("%T: %v", v, err)
		}
	}
	short := []string{"Your password expires in 3 days.", "Welcome"}
	if got := FitMessages(short); strings.Join(got, "|") != strings.Join(short, "|") {
		t.Fatalf("short messages changed: %q", got)
	}
	// A cut never splits a rune.
	if got := FitMessages([]string{strings.Repeat("é", MaxMessage)}); !strings.HasSuffix(got[0], "é") {
		t.Fatal("cut inside a rune")
	}
}

// Every refusal code fits the length FitMessages reserves.
func TestRefusalCodesFitMaxCodeLen(t *testing.T) {
	for _, c := range []string{CodeBadRequest, CodeUnsupportedKind, CodeDeviceUnknown, CodeKindNotEnabled, CodeLoginNotEnabled,
		CodeBusy, CodeAccountUnavailable, CodeAccountRefused, CodePAMFailed, CodeSpawnFailed, CodeConfigUnreadable,
		CodeInternal, CodeVersionMismatch, CodeStartTimeout} {
		if len(c) > maxCodeLen {
			t.Errorf("%s is longer than %d", c, maxCodeLen)
		}
	}
}

// Messages ride beside started and refused, never beside a probe or exit,
// and reach the client's Session and RefusalError.
func TestResponseMessages(t *testing.T) {
	for _, r := range []Response{
		{Started: &Started{SessionID: "x"}, Messages: []string{"motd"}},
		{Refused: &Refused{Code: CodeAccountRefused}, Messages: []string{"logins disabled"}},
	} {
		b, err := encode(r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readResponse(bytes.NewReader(b))
		if err != nil || len(got.Messages) != 1 {
			t.Fatalf("%+v: %+v, %v", r, got, err)
		}
	}
	b, _ := encode(Response{Probe: &Probe{}, Messages: []string{"x"}})
	if _, err := readResponse(bytes.NewReader(b)); err == nil {
		t.Fatal("messages beside a probe were read")
	}
	var r *RefusalError
	if err := clientRefusal(CodeAccountRefused, []string{"locked"}, FullDiskAccessDenied); !asRefusal(err, &r) || r.Messages[0] != "locked" || r.FullDiskAccess != FullDiskAccessDenied {
		t.Fatalf("refusal %v", err)
	}
}

func asRefusal(err error, r **RefusalError) bool {
	e, ok := err.(*RefusalError)
	*r = e
	return ok
}

// One profile progress may precede the reply when the reader takes it; a
// second one, an unknown stage, or any progress without a reader is refused.
func TestReadHelperReplyProgress(t *testing.T) {
	readKind := func(kind string, onProgress func(string), msgs ...any) (HelperReply, error) {
		var buf bytes.Buffer
		for _, m := range msgs {
			if err := writeMessage(&buf, m); err != nil {
				t.Fatal(err)
			}
		}
		return ReadHelperReply(&buf, kind, onProgress)
	}
	read := func(onProgress func(string), msgs ...any) (HelperReply, error) {
		return readKind(KindSFTP, onProgress, msgs...)
	}
	var stages []string
	note := func(s string) { stages = append(stages, s) }
	reply, err := read(note, HelperProgress{Stage: ProgressProfile}, HelperReply{Started: true, Messages: []string{"m"}})
	if err != nil || !reply.Started || len(stages) != 1 || len(reply.Messages) != 1 {
		t.Fatalf("reply %+v, %v, stages %q", reply, err, stages)
	}
	if reply, err := read(nil, HelperReply{Started: true, Confined: true, Home: "x"}); err != nil || !reply.Confined || reply.Home != "x" {
		t.Fatalf("view reply %+v, %v", reply, err)
	}
	for name, msgs := range map[string][]any{
		"two progress":            {HelperProgress{Stage: ProgressProfile}, HelperProgress{Stage: ProgressProfile}, HelperReply{Started: true}},
		"unknown stage":           {HelperProgress{Stage: "logon"}, HelperReply{Started: true}},
		"confined on a refusal":   {HelperReply{Refused: CodeSpawnFailed, Confined: true}},
		"home on a refusal":       {HelperReply{Refused: CodeSpawnFailed, Home: "."}},
		"whole disk on a refusal": {HelperReply{Refused: CodeSpawnFailed, WholeDisk: true}},
		"home without confined":   {HelperReply{Started: true, Home: "x"}},
		"absolute home":           {HelperReply{Started: true, Confined: true, Home: "/x"}},
		"home outside the root":   {HelperReply{Started: true, Confined: true, Home: "../x"}},
		"whole disk unconfined":   {HelperReply{Started: true, WholeDisk: true}},
	} {
		if _, err := read(note, msgs...); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	for name, reply := range map[string]HelperReply{
		"confined":   {Started: true, Confined: true},
		"home":       {Started: true, Confined: true, Home: "x"},
		"whole disk": {Started: true, Confined: true, WholeDisk: true},
	} {
		if _, err := readKind(KindTerminal, nil, reply); err == nil {
			t.Errorf("%s view on a terminal session: read", name)
		}
	}
	if reply, err := readKind(KindTerminal, nil, HelperReply{Started: true}); err != nil || !reply.Started {
		t.Errorf("terminal start without a view: %+v, %v", reply, err)
	}
	if _, err := read(nil, HelperProgress{Stage: ProgressProfile}, HelperReply{Started: true}); err == nil {
		t.Error("progress read without a reader")
	}
}

// fakeTimer is a startTimer the test fires by hand.
type fakeTimer struct {
	armed bool
	d     time.Duration
	f     func()
}

func (t *fakeTimer) Stop() bool                 { was := t.armed; t.armed = false; return was }
func (t *fakeTimer) Reset(d time.Duration) bool { was := t.armed; t.armed, t.d = true, d; return was }
func (t *fakeTimer) fire() {
	if t.armed {
		t.armed = false
		t.f()
	}
}

func fakeWatch() (*startWatch, *fakeTimer, *int) {
	ft := &fakeTimer{}
	kills := 0
	w := newStartWatch(func(d time.Duration, f func()) startTimer {
		ft.armed, ft.d, ft.f = true, d, f
		return ft
	}, func() { kills++ })
	return w, ft, &kills
}

// The start bound is helperStartTimeout; a profile progress re-arms it to
// profileStartTimeout, so a profile load past 30 s still starts; past the
// profile bound the helper is killed and the start timed out; a bound that
// fired before the progress stays fired.
func TestStartWatch(t *testing.T) {
	w, ft, kills := fakeWatch()
	if ft.d != helperStartTimeout {
		t.Fatalf("armed for %v", ft.d)
	}
	w.progress()
	if ft.d != profileStartTimeout || !ft.armed {
		t.Fatalf("after progress armed %v for %v", ft.armed, ft.d)
	}
	if w.stop() || *kills != 0 {
		t.Fatal("a start within the profile bound timed out")
	}

	w, ft, kills = fakeWatch()
	w.progress()
	ft.fire()
	if !w.stop() || *kills != 1 {
		t.Fatalf("past the profile bound: timed out %v, kills %d", w.timedOut.Load(), *kills)
	}

	w, ft, kills = fakeWatch()
	ft.fire()
	w.progress()
	if ft.armed || !w.stop() || *kills != 1 {
		t.Fatalf("fired before the progress: re-armed %v, kills %d", ft.armed, *kills)
	}

	// The bound expired but its callback has not run yet when the reply
	// arrives: the start still timed out, since the kill is on its way.
	w, ft, _ = fakeWatch()
	ft.armed = false
	if !w.stop() {
		t.Fatal("an expired bound whose callback is pending reported a start in time")
	}
}

// A stream mux refuses an ack, for a live stream and for an unknown id
// alike: acks belong to passed sockets, which a mux never carries (the
// Windows helper's only refusal of one).
func TestForwardMuxRefusesAnAck(t *testing.T) {
	m := NewForwardMux(func(FwdMsg) error { return nil })
	if _, err := m.Open(1); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint32{1, 9} {
		if err := m.Deliver(FwdMsg{Type: FwdAck, ID: id}); err == nil {
			t.Errorf("ack of id %d delivered", id)
		}
	}
}

// A start past its bound is refused start_timeout.
func TestStartTimeoutRefusalCode(t *testing.T) {
	if got := startFailureCode(errHelperTimeout); got != CodeStartTimeout {
		t.Fatalf("code %q", got)
	}
}
