package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	jtiLogFile  = "session_jti.log"
	jtiLockFile = ".jti.lock"

	// maxJTIEntries bounds the spent tickets held until their expiry.
	maxJTIEntries = 4096
	// jtiHold is how long after its exp a spent ticket stays refused: the
	// verification skew.
	jtiHold = ticketSkew
	// jtiBlindWindow is how long an unreadable log refuses every spend, so
	// every entry the lost log could hold has expired by then: a spend at
	// agent time s passed VerifyTicket, so iat <= s + ticketSkew and exp -
	// iat <= maxTicketLifetime, and its until = exp + jtiHold <= s + 120 s.
	jtiBlindWindow = ticketSkew + maxTicketLifetime + jtiHold
)

var (
	// ErrJTILogLocked means another process holds the identity's jti log.
	ErrJTILogLocked = errcode.New(errcode.JTILogLocked)
	// errReplayed means the jti was already spent.
	errReplayed = errors.New("ticket already used")
	// errJTIUnavailable means the jti cannot be recorded now: the cache is
	// full, the log is unreadable, or the append failed.
	errJTIUnavailable = errcode.New(errcode.JTIUnavailable)
)

// jtiRecord is one line of session_jti.log.
type jtiRecord struct {
	JTI   string `json:"jti"`
	Until int64  `json:"until"`
}

// jtiWriter is the log's append handle; *os.File in production.
type jtiWriter interface {
	io.Writer
	Sync() error
	Close() error
}

// JTILog is the persisted replay cache of one device identity: every spent
// ticket id with the time until which it stays refused. The process holding
// .jti.lock is its only writer. Spend appends and fsyncs before it returns,
// so a restart cannot reopen a replay window. It is safe for concurrent use.
type JTILog struct {
	path    string
	release func()
	now     func() time.Time

	mu      sync.Mutex
	entries map[string]time.Time
	out     jtiWriter // nil while blind
	lines   int       // records in the file
	blind   time.Time // spends are refused before this time
	// stale means the file may not match entries: it could not be read at
	// open, it ended in a partial line, or an append failed and may have left
	// one. The next spend rewrites it from entries before appending.
	stale  bool
	closed bool
}

// OpenJTILog takes .jti.lock in the identity directory dir for the life of
// the log and loads session_jti.log, dropping expired entries. A log it cannot
// read or parse leaves the cache blind for jtiBlindWindow, after which a fresh
// log starts. It returns ErrJTILogLocked when another holder has the lock.
// now is the clock; nil means time.Now.
func OpenJTILog(dir string, now func() time.Time) (*JTILog, error) {
	if now == nil {
		now = time.Now
	}
	release, err := lockJTI(filepath.Join(dir, jtiLockFile))
	if err != nil {
		return nil, err
	}
	l := &JTILog{path: filepath.Join(dir, jtiLogFile), release: release, now: now, entries: map[string]time.Time{}}
	start := now()
	if err := l.load(start); err != nil {
		l.entries = map[string]time.Time{}
		l.lines = 0
		l.stale = true
		l.blind = start.Add(jtiBlindWindow)
		return l, nil
	}
	// A failure here leaves the file closed; Spend retries it and refuses
	// until it succeeds.
	if l.compactLocked(l.stale) == nil {
		l.stale = false
	}
	return l, nil
}

func lockJTI(path string) (func(), error) {
	f, err := security.OpenLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", jtiLockFile, err)
	}
	held, err := security.TryLockFile(f)
	if err != nil || !held {
		f.Close()
		if err == nil {
			err = ErrJTILogLocked
		}
		return nil, err
	}
	return func() {
		_ = security.UnlockFile(f)
		f.Close()
	}, nil
}

// load reads the file into entries. An absent file is empty. A final record
// without its newline was never acknowledged (Spend returns nil only after
// the whole line is synced): it is dropped and the file marked stale so it is
// rewritten without it. Any other malformed line fails the load.
func (l *JTILog) load(now time.Time) error {
	data, err := security.ReadPrivateFile(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = data[:bytes.LastIndexByte(data, '\n')+1]
		l.stale = true
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var r jtiRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.JTI == "" {
			return fmt.Errorf("%s: malformed record", jtiLogFile)
		}
		l.lines++
		if until := time.Unix(r.Until, 0); until.After(now) {
			l.entries[r.JTI] = until
		}
	}
	return sc.Err()
}

// Spend records jti as used until until. It returns errReplayed for a jti
// already held and errJTIUnavailable when it cannot record it; in both cases
// the ticket must be refused. The record is durable when Spend returns nil.
func (l *JTILog) Spend(jti string, until time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.closed || now.Before(l.blind) {
		return errJTIUnavailable
	}
	for id, u := range l.entries {
		if !u.After(now) {
			delete(l.entries, id)
		}
	}
	if u, ok := l.entries[jti]; ok && u.After(now) {
		return errReplayed
	}
	if len(l.entries) >= maxJTIEntries {
		return errJTIUnavailable
	}
	// After the blind window an unreadable log is replaced by a fresh one.
	if err := l.compactLocked(l.stale); err != nil {
		return errJTIUnavailable
	}
	l.stale = false
	line, err := json.Marshal(jtiRecord{JTI: jti, Until: until.Unix()})
	if err != nil {
		return errJTIUnavailable
	}
	if _, err := l.out.Write(append(line, '\n')); err != nil {
		l.stale = true
		return errJTIUnavailable
	}
	if err := l.out.Sync(); err != nil {
		l.stale = true
		return errJTIUnavailable
	}
	l.lines++
	l.entries[jti] = until
	return nil
}

// compactLocked rewrites the file atomically with the live entries when force
// is set or when it holds more than twice as many records, and keeps it open
// for appending. entries holds no expired entry when it is called.
func (l *JTILog) compactLocked(force bool) error {
	rewrite := force || l.lines > 2*len(l.entries)
	if !rewrite && l.out != nil {
		return nil
	}
	if !rewrite {
		f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0)
		if err == nil {
			l.out = f
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if l.out != nil {
		_ = l.out.Close()
		l.out = nil
	}
	var buf bytes.Buffer
	for id, u := range l.entries {
		line, err := json.Marshal(jtiRecord{JTI: id, Until: u.Unix()})
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if err := security.WritePrivateFileAtomic(l.path, buf.Bytes()); err != nil {
		return err
	}
	l.lines = len(l.entries)
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	l.out = f
	return nil
}

// Close closes the log and releases .jti.lock. Later spends are refused.
func (l *JTILog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var err error
	if l.out != nil {
		err = l.out.Close()
		l.out = nil
	}
	l.release()
	return err
}
