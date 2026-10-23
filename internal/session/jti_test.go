package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openJTI(t *testing.T, dir string, clk *fakeClock) *JTILog {
	t.Helper()
	l, err := OpenJTILog(dir, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A spent jti stays refused across a restart until it expires.
func TestJTILogPersistsSpends(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	l := openJTI(t, dir, clk)
	if err := l.Spend("a", testNow.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := l.Spend("a", testNow.Add(90*time.Second)); !errors.Is(err, errReplayed) {
		t.Fatalf("second spend = %v, want errReplayed", err)
	}
	l.Close()

	l = openJTI(t, dir, clk)
	defer l.Close()
	if err := l.Spend("a", testNow.Add(90*time.Second)); !errors.Is(err, errReplayed) {
		t.Fatalf("spend after a restart = %v, want errReplayed", err)
	}
	clk.Advance(91 * time.Second)
	if err := l.Spend("a", clk.Now().Add(90*time.Second)); err != nil {
		t.Fatalf("spend after expiry = %v", err)
	}
}

// Expired entries are dropped, and a file with more than twice the live
// entries is rewritten.
func TestJTILogCompacts(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	l := openJTI(t, dir, clk)
	for _, id := range []string{"a", "b", "c", "d"} {
		if err := l.Spend(id, testNow.Add(10*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(20 * time.Second)
	if err := l.Spend("e", clk.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	l.Close()
	data, err := os.ReadFile(filepath.Join(dir, jtiLogFile))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(data), "\n"); lines != 1 || !strings.Contains(string(data), `"e"`) {
		t.Fatalf("log after compaction:\n%s\nwant only e", data)
	}
}

// The log has one holder; a second open on the same identity is refused.
func TestJTILogHasOneHolder(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	l := openJTI(t, dir, clk)
	if _, err := OpenJTILog(dir, clk.Now); !errors.Is(err, ErrJTILogLocked) {
		t.Fatalf("second open = %v, want ErrJTILogLocked", err)
	}
	l.Close()
	openJTI(t, dir, clk).Close()
}

// The fail-closed window covers the longest hold of a ticket spent at agent
// time s: iat <= s + 30 s, exp <= iat + 60 s, held to exp + 30 s.
func TestJTIBlindWindowIs120Seconds(t *testing.T) {
	if jtiBlindWindow != 120*time.Second {
		t.Fatalf("jtiBlindWindow = %v, want 120s", jtiBlindWindow)
	}
}

// halfWriter writes the first half of its first append and then fails; later
// writes go through.
type halfWriter struct {
	jtiWriter
	failed bool
}

func (w *halfWriter) Write(p []byte) (int, error) {
	if w.failed {
		return w.jtiWriter.Write(p)
	}
	w.failed = true
	n, _ := w.jtiWriter.Write(p[:len(p)/2])
	return n, errors.New("disk full")
}

// syncFailWriter writes the whole line but fails its first Sync, as fsync
// can after the data reached the page cache.
type syncFailWriter struct {
	jtiWriter
	failed bool
}

func (w *syncFailWriter) Sync() error {
	if w.failed {
		return w.jtiWriter.Sync()
	}
	w.failed = true
	return errors.New("fsync failed")
}

// A failed append (a partial line, or a full line whose fsync failed) is
// rewritten away before the next append, so the log loads cleanly at the next
// start and the refused jti stays unspent.
func TestJTILogRewritesAfterAFailedAppend(t *testing.T) {
	for name, wrap := range map[string]func(jtiWriter) jtiWriter{
		"partial write": func(w jtiWriter) jtiWriter { return &halfWriter{jtiWriter: w} },
		"failed sync":   func(w jtiWriter) jtiWriter { return &syncFailWriter{jtiWriter: w} },
	} {
		t.Run(name, func(t *testing.T) {
			dir, clk := t.TempDir(), newFakeClock(testNow)
			l := openJTI(t, dir, clk)
			until := testNow.Add(90 * time.Second)
			if err := l.Spend("a", until); err != nil {
				t.Fatal(err)
			}
			l.mu.Lock()
			l.out = wrap(l.out)
			l.mu.Unlock()
			if err := l.Spend("b", until); !errors.Is(err, errJTIUnavailable) {
				t.Fatalf("spend on a failing append = %v, want errJTIUnavailable", err)
			}
			if err := l.Spend("c", until); err != nil {
				t.Fatalf("spend after a failed append = %v", err)
			}
			l.Close()

			l = openJTI(t, dir, clk)
			defer l.Close()
			for _, id := range []string{"a", "c"} {
				if err := l.Spend(id, until); !errors.Is(err, errReplayed) {
					t.Fatalf("spend of %s after a restart = %v, want errReplayed", id, err)
				}
			}
			if err := l.Spend("b", until); err != nil {
				t.Fatalf("spend of the failed jti after a restart = %v", err)
			}
		})
	}
}

// An unreadable log refuses every spend for 120 s after start, then starts
// fresh.
func TestJTILogFailsClosedOnACorruptFile(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	path := filepath.Join(dir, jtiLogFile)
	if err := os.WriteFile(path, []byte("{\"jti\":\"a\",\"until\":1}\nnot json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openJTI(t, dir, clk)
	defer l.Close()
	clk.Advance(jtiBlindWindow - time.Second)
	if err := l.Spend("b", clk.Now().Add(time.Minute)); !errors.Is(err, errJTIUnavailable) {
		t.Fatalf("spend inside the window = %v, want errJTIUnavailable", err)
	}
	clk.Advance(time.Second)
	if err := l.Spend("b", clk.Now().Add(time.Minute)); err != nil {
		t.Fatalf("spend after the window = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "not json") {
		t.Fatalf("the corrupt log was kept:\n%s", data)
	}
}

// A final record cut before its newline was never acknowledged: it is dropped
// and the file rewritten without it, with no blind window, while the records
// before it stay held.
func TestJTILogDropsATornLastRecord(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	path := filepath.Join(dir, jtiLogFile)
	held := testNow.Add(time.Minute).Unix()
	content := fmt.Sprintf("{\"jti\":\"a\",\"until\":%d}\n{\"jti\":\"b\",\"until\":%d", held, held)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openJTI(t, dir, clk)
	defer l.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("{\"jti\":\"a\",\"until\":%d}\n", held); string(data) != want {
		t.Fatalf("log after open:\n%q\nwant %q", data, want)
	}
	if err := l.Spend("a", clk.Now().Add(time.Minute)); !errors.Is(err, errReplayed) {
		t.Fatalf("spend of a = %v, want errReplayed", err)
	}
	if err := l.Spend("b", clk.Now().Add(time.Minute)); err != nil {
		t.Fatalf("spend of the torn jti = %v", err)
	}
}

// A malformed line that ends in its newline is not a torn tail: the log
// stays blind.
func TestJTILogRefusesAMalformedTerminatedLine(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	if err := os.WriteFile(filepath.Join(dir, jtiLogFile), []byte("{\"jti\":\"a\",\"until\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openJTI(t, dir, clk)
	defer l.Close()
	if err := l.Spend("b", clk.Now().Add(time.Minute)); !errors.Is(err, errJTIUnavailable) {
		t.Fatalf("spend = %v, want errJTIUnavailable", err)
	}
}

// A full cache refuses new spends.
func TestJTILogIsBounded(t *testing.T) {
	dir, clk := t.TempDir(), newFakeClock(testNow)
	l := openJTI(t, dir, clk)
	defer l.Close()
	l.mu.Lock()
	for i := range maxJTIEntries {
		l.entries[string(rune(0x10000+i))] = testNow.Add(time.Minute)
	}
	l.lines = maxJTIEntries
	l.mu.Unlock()
	if err := l.Spend("new", testNow.Add(time.Minute)); !errors.Is(err, errJTIUnavailable) {
		t.Fatalf("spend into a full cache = %v, want errJTIUnavailable", err)
	}
}
