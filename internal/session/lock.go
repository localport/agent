package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	sessionsLockFile = ".sessions.lock"
	// legacyReplayFiles are the files of the ticket replay cache, which no
	// session uses; LockSessions removes them.
	legacyReplayLog  = "session_jti.log"
	legacyReplayLock = ".jti.lock"
)

// ErrSessionsLocked means another process serves this identity's sessions.
var ErrSessionsLocked = errcode.New(errcode.SessionsLocked)

// SessionsLock is the single-process guard for serving one device identity's
// sessions: two processes serving them would each take recording slots and
// spool entries for the same identity.
type SessionsLock struct {
	release func()
}

// LockSessions takes .sessions.lock in the identity directory dir until
// Close. It returns ErrSessionsLocked when another holder has it.
func LockSessions(dir string) (*SessionsLock, error) {
	f, err := security.OpenLockFile(filepath.Join(dir, sessionsLockFile))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", sessionsLockFile, err)
	}
	held, err := security.TryLockFile(f)
	if err != nil || !held {
		f.Close()
		if err == nil {
			err = ErrSessionsLocked
		}
		return nil, err
	}
	for _, name := range []string{legacyReplayLog, legacyReplayLock} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			// Harmless leftovers; the lock is held either way.
			continue
		}
	}
	return &SessionsLock{release: func() {
		_ = security.UnlockFile(f)
		f.Close()
	}}, nil
}

// Close releases the lock. It is safe to call more than once.
func (l *SessionsLock) Close() error {
	if l != nil && l.release != nil {
		l.release()
		l.release = nil
	}
	return nil
}
