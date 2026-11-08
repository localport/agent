//go:build linux || darwin

package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/recording"
)

func expectFailedOpen(t *testing.T, client *captureClient) recording.FailedOpen {
	t.Helper()
	select {
	case f := <-client.failedOpens:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("no failed open was sent")
		return recording.FailedOpen{}
	}
}

// Every start that cannot record sends one failed open under both policies,
// signed over the key hash the certificate names. A Strict channel is refused
// and a Best effort one runs unrecorded.
func TestFailedRecordingStartSendsOneFailedOpen(t *testing.T) {
	saved, savedSealer := strictOpenTimeout, newRecordingSealer
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout, newRecordingSealer = saved, savedSealer })
	cases := []struct {
		name      string
		block     bool
		changeKey bool
		sealer    func(string, []byte) (*recording.Sealer, error)
	}{
		{name: "open timeout", block: true},
		{name: "held key changed", changeKey: true},
		{name: "sealer error", sealer: func(string, []byte) (*recording.Sealer, error) { return nil, errors.New("no sealer") }},
	}
	for _, tc := range cases {
		for _, policy := range []string{RecPolicyStrict, RecPolicyBestEffort} {
			t.Run(tc.name+"/"+policy, func(t *testing.T) {
				newRecordingSealer = savedSealer
				if tc.sealer != nil {
					newRecordingSealer = tc.sealer
				}
				client := &captureClient{block: tc.block, opens: make(chan capturedOpen, 2), failedOpens: make(chan recording.FailedOpen, 2)}
				f, keySum, _ := recordingFixture(t, client)
				o := f.defaults()
				o.kind = "ssh"
				o.rec = &certRec{Policy: policy, PubSHA256: keySum}
				var changed atomic.Bool
				held := f.srv.cfg.RecordingKey
				f.srv.cfg.RecordingKey = func() ([]byte, [sha256.Size]byte, bool) {
					key, sum, ok := held()
					if changed.Load() {
						sum = sha256.Sum256([]byte("another team key"))
					}
					return key, sum, ok
				}
				c := f.connect(t, o)
				changed.Store(tc.changeKey)
				sess, err := c.NewSession()
				if err != nil {
					t.Fatalf("channel: %v", err)
				}
				var exitErr *ssh.ExitError
				err = sess.Run("ls -l /tmp")
				ran := errors.As(err, &exitErr) && exitErr.ExitStatus() == 3
				if ran != (policy == RecPolicyBestEffort) {
					t.Fatalf("run under %s = %v", policy, err)
				}

				got := expectFailedOpen(t, client)
				wantKey, _ := base64.RawURLEncoding.DecodeString(keySum)
				if got.Reason != recording.ReasonRecordingFailed || got.Channels != 1 || !bytes.Equal(got.KeySHA256, wantKey) || len(got.Certificate) == 0 || got.SessionID == "" {
					t.Fatalf("failed open %+v", got)
				}
				select {
				case extra := <-client.failedOpens:
					t.Fatalf("a second failed open: %+v", extra)
				case <-time.After(100 * time.Millisecond):
				}
			})
		}
	}
}

func TestDecodeExit(t *testing.T) {
	for _, tc := range []struct {
		code   int32
		goos   string
		status int
		signal string
	}{
		{0, "linux", 0, ""},
		{137, "linux", 137, ""},
		{-9, "linux", 137, "KILL"},
		{-15, "darwin", 143, "TERM"},
		{-28, "linux", 156, "WINCH@localport.io"},
		{-1073741819, "windows", 3221225477, ""}, // 0xC0000005
	} {
		status, signal := decodeExit(tc.code, tc.goos)
		if status != tc.status || signal != tc.signal {
			t.Errorf("decodeExit(%d, %s) = %d, %q; want %d, %q", tc.code, tc.goos, status, signal, tc.status, tc.signal)
		}
	}
}

// A process killed by a signal reaches the client as exit-signal.
func TestAKilledHelperSendsExitSignal(t *testing.T) {
	f := newSSHFixture(t, nil)
	o := f.defaults()
	o.kind = "ssh"
	c := f.connect(t, o)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var exitErr *ssh.ExitError
	if err := sess.Run("killed"); !errors.As(err, &exitErr) || exitErr.Signal() != "KILL" {
		t.Fatalf("run = %v, want exit-signal KILL", err)
	}
}

// A spool refusal names itself; anything else is recording_failed.
func TestStartFailureReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("create: %w", recording.ErrSpoolFull), recording.ReasonSpoolFull},
		{fmt.Errorf("create: %w", recording.ErrDiskLow), recording.ReasonDiskLow},
		{recording.ErrNoSessionMux, recording.ReasonRecordingFailed},
	} {
		if got := startFailureReason(tc.err); got != tc.want {
			t.Errorf("startFailureReason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// An abort after the open reports the failed start once; a nil recorder, as
// an unrecorded channel holds, is a no-op.
func TestRecorderAbortReportsTheFailedStart(t *testing.T) {
	r, _ := newTestRecorder(t, RecPolicyBestEffort, &fakeHandoff{})
	calls := 0
	r.onAbort = func() { calls++ }
	r.abort()
	if calls != 1 {
		t.Fatalf("onAbort ran %d times, want 1", calls)
	}
	var none *sessionRecorder
	none.abort()
}

// A failing open leaves the sealer sealed: its DEK is gone.
func TestFailedOpenDiscardsTheSealer(t *testing.T) {
	saved, savedSealer := strictOpenTimeout, newRecordingSealer
	strictOpenTimeout = 200 * time.Millisecond
	t.Cleanup(func() { strictOpenTimeout, newRecordingSealer = saved, savedSealer })
	sealers := make(chan *recording.Sealer, 1)
	newRecordingSealer = func(id string, key []byte) (*recording.Sealer, error) {
		s, err := savedSealer(id, key)
		sealers <- s
		return s, err
	}
	client := &captureClient{block: true, opens: make(chan capturedOpen, 1)}
	f, keySum, _ := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	o.rec = &certRec{Policy: RecPolicyStrict, PubSHA256: keySum}
	c := f.connect(t, o)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatalf("channel: %v", err)
	}
	if err := sess.Run("ls -l /tmp"); err == nil {
		t.Fatal("a Strict channel ran with its open failed")
	}
	if _, err := (<-sealers).Seal(nil, true); !errors.Is(err, recording.ErrSealed) {
		t.Fatalf("Seal after the failed open = %v, want ErrSealed", err)
	}
}

// A resume stream counts its recorded starts from zero.
func TestResumeStreamCountsRecordedStartsFromZero(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	rec := &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	o := f.defaults()
	o.kind, o.rec = "ssh", rec
	rc := f.connectResumableAs(t, o)
	run := func() int32 {
		t.Helper()
		s, err := rc.client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Run("ls -l /tmp")
		return (<-client.opens).channels
	}
	if got := run(); got != 1 {
		t.Fatalf("first stream's first start carried %d", got)
	}
	rc.cut(t)
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.rec = "ssh", rec }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if got := run(); got != 1 {
		t.Fatalf("resume stream's first start carried %d", got)
	}
}

// Each recorded start on a stream counts up.
func TestRecordedStartsCountCumulatively(t *testing.T) {
	client := &captureClient{opens: make(chan capturedOpen, 2)}
	f, keySum, _ := recordingFixture(t, client)
	o := f.defaults()
	o.kind = "ssh"
	o.rec = &certRec{Policy: RecPolicyBestEffort, PubSHA256: keySum}
	c := f.connect(t, o)
	for want := int32(1); want <= 2; want++ {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatalf("channel: %v", err)
		}
		_ = sess.Run("ls -l /tmp")
		if got := (<-client.opens).channels; got != want {
			t.Fatalf("open %d carried count %d", want, got)
		}
	}
}
