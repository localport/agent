package identity

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/localport/agent/internal/security"
)

// A device renewal does not replace the device's credential. The control
// plane issues the renewed certificate as pending and keeps the current one
// live until the device registers with the pending one, so the store holds
// both until then:
//
//	meta.json     current credential, what Load returns
//	pending.json  renewed credential, what LoadPending returns; it records
//	              the serial it was renewed from and counts only while that
//	              serial is current
//
// The registering side presents the pending credential and calls Promote
// after the edge acknowledges it. Promote makes it current and deletes the
// previous key. Save, the renewal and Promote all write under the
// credential's renewal lock, so none of them sweeps files another is writing.

// ErrNoPending means the credential has no pending renewal.
var ErrNoPending = errors.New("no pending credential")

// ErrCredentialReplaced means the current credential changed while a renewal
// was in flight, so the renewed certificate belongs to a credential this
// machine no longer holds.
var ErrCredentialReplaced = errors.New("the credential was replaced during renewal")

// ErrPendingChanged means the pending credential is not the one the caller
// registered with. A later renewal replaced it.
var ErrPendingChanged = errors.New("the pending credential changed")

// saveLockWait bounds how long Save waits for a renewal in flight: the
// renewal's retry budget plus two request timeouts, one for an attempt
// started just before the budget ran out and one of slack.
const saveLockWait = DefaultRetryBudget + 2*requestTimeout

// lockPollInterval is how often a waiting writer retries the lock. File locks
// have no portable wait with a deadline or cancellation.
const lockPollInterval = 200 * time.Millisecond

// LoadPending reads the pending credential, or returns ErrNoPending.
func (s *Store) LoadPending(ref Ref) (*Material, error) {
	_, pending, err := s.readPair(ref)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, ErrNoPending
	}
	m, err := loadMaterial(s.dir(ref), *pending)
	if err != nil {
		return nil, errUnreadable.With(err, "the renewed credential of "+ref.String())
	}
	return m, nil
}

// readPair reads the current metadata and the pending metadata that belongs
// to it. pending is nil when pending.json is absent or was renewed from a
// credential that is no longer current.
func (s *Store) readPair(ref Ref) (cur Meta, pending *Meta, err error) {
	dir := s.dir(ref)
	if err := s.trusted(dir); err != nil {
		return Meta{}, nil, err
	}
	cur, err = readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		return Meta{}, nil, err
	}
	if s.afterMetaRead != nil {
		s.afterMetaRead()
	}
	p, err := readMeta(filepath.Join(dir, pendingFile))
	if errors.Is(err, fs.ErrNotExist) {
		return cur, nil, nil
	}
	if err != nil {
		return Meta{}, nil, err
	}
	if p.RenewedFrom != cur.Serial {
		return cur, nil, nil
	}
	return cur, &p, nil
}

// savePending stores m as the pending credential of the current one, whose
// serial is renewedFrom. It stores the certificate only; m.DeviceKeys is the
// caller's to pass to TicketKeys.Replace. The caller holds the renewal lock.
// A pending credential already present is replaced, as the control plane
// revokes it when it issues the next one. m.Meta is completed in place, so
// the caller's Material names the files as stored.
func (s *Store) savePending(m *Material, renewedFrom string) (Ref, error) {
	ref, dir, err := s.prepare(m)
	if err != nil {
		return Ref{}, err
	}
	m.Meta.RenewedFrom = renewedFrom
	cur, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		return Ref{}, errUnreadable.With(err, "the current credential")
	}
	if cur.Serial != renewedFrom {
		return Ref{}, ErrCredentialReplaced
	}
	if err := writeKeyMaterial(dir, m); err != nil {
		return Ref{}, err
	}
	if err := writeMeta(dir, pendingFile, m.Meta); err != nil {
		return Ref{}, err
	}
	s.sweep(dir, cur.Cert, cur.Key.File, m.Meta.Cert, m.Meta.Key.File)
	return ref, nil
}

// Promote makes the pending credential with the given serial current and
// deletes the previous certificate and key. Call it only after the edge has
// acknowledged a registration with that credential.
//
// Promoting a serial that is already current succeeds. When nothing is
// pending it also removes a stale pending.json and the superseded pair, which
// repairs a crash between the two writes below; a pending renewal of the
// current credential is kept.
//
// It returns ErrRenewalInProgress while a renewal holds the lock, ErrNoPending
// when nothing is pending, ErrPendingChanged when a later renewal replaced the
// pending credential, and the read error when the credential is unreadable.
func (s *Store) Promote(ref Ref, serial string) error {
	release, held, err := s.tryLock(ref)
	if err != nil {
		return err
	}
	if !held {
		return ErrRenewalInProgress
	}
	defer release()

	cur, pending, err := s.readPair(ref)
	if err != nil {
		return err
	}
	dir := s.dir(ref)
	if cur.Serial == serial {
		// A later renewal of the current credential stays pending.
		if pending != nil {
			return nil
		}
		// A crash after the meta.json write leaves pending.json and the
		// superseded pair behind; finish the cleanup.
		if err := removeIfExists(filepath.Join(dir, pendingFile)); err != nil {
			return err
		}
		s.sweep(dir, cur.Cert, cur.Key.File)
		return nil
	}
	if pending == nil {
		return ErrNoPending
	}
	if pending.Serial != serial {
		return ErrPendingChanged
	}
	// The pair must load before it replaces the only other usable one.
	m, err := loadMaterial(dir, *pending)
	if err != nil {
		return errUnreadable.With(err, "the renewed credential of "+ref.String())
	}
	if _, err := m.TLSCertificate(); err != nil {
		return errUnreadable.With(err, "the renewed credential of "+ref.String())
	}

	promoted := *pending
	promoted.RenewedFrom = ""
	if err := writeMeta(dir, metaFile, promoted); err != nil {
		return err
	}
	if err := removeIfExists(filepath.Join(dir, pendingFile)); err != nil {
		return err
	}
	s.sweep(dir, promoted.Cert, promoted.Key.File)
	return nil
}

// tryLock takes the credential's renewal lock without blocking. It lives in
// the credential's lock directory (LockDir), so it is scoped to one credential
// and exists whether or not the credential does, and the OS releases it if
// the holder dies. It returns ErrStoreBusy while a purge holds the store lock.
func (s *Store) tryLock(ref Ref) (release func(), held bool, err error) {
	unshare, err := s.tryShareStore()
	if err != nil {
		return nil, false, err
	}
	path, err := s.lockFileAt(ref.Path(), lockFile)
	if err != nil {
		unshare()
		return nil, false, err
	}
	unlock, held, err := tryLockFile(path, false)
	if err != nil || !held {
		unshare()
		return nil, false, err
	}
	return func() { unlock(); unshare() }, true, nil
}

// lockCredential takes the store lock shared, then the lock file name of the
// credential at rel (a path relative to Root), each waiting up to wait. It
// returns ErrStoreBusy when a purge still holds the store lock then, and busy
// when another writer holds the credential lock. The returned func releases
// both.
// onAttempt, when set, runs after each attempt on the credential lock.
func (s *Store) lockCredential(ctx context.Context, rel, name string, wait time.Duration, busy error, onAttempt func(held bool)) (func(), error) {
	unshare, err := s.shareStore(ctx, wait)
	if err != nil {
		return nil, err
	}
	path, err := s.lockFileAt(rel, name)
	if err != nil {
		unshare()
		return nil, err
	}
	release, err := waitLockFile(ctx, path, false, wait, busy, onAttempt)
	if err != nil {
		unshare()
		return nil, err
	}
	return func() { release(); unshare() }, nil
}

// waitLock takes the renewal lock, retrying for up to wait. It returns
// ErrRenewalInProgress when the lock is still held then, and ctx.Err() when
// ctx ends first.
func (s *Store) waitLock(ctx context.Context, ref Ref, wait time.Duration) (func(), error) {
	return s.waitLockAt(ctx, ref.Path(), wait)
}

// waitLockAt is waitLock for the credential at rel, a path relative to Root.
func (s *Store) waitLockAt(ctx context.Context, rel string, wait time.Duration) (func(), error) {
	release, err := s.lockCredential(ctx, rel, lockFile, wait, ErrRenewalInProgress, s.renewLockAttempt)
	if err != nil || s.renewLockReleasing == nil {
		return release, err
	}
	return func() { s.renewLockReleasing(); release() }, nil
}

// lockOpened, when set, runs between a lock file's open and its lock; tests
// delete the file there.
var lockOpened func(path string)

// tryLockFile takes the file lock at path without blocking, shared or
// exclusive. The lock is per open file, so two holders in one process exclude
// each other too.
func tryLockFile(path string, shared bool) (release func(), held bool, err error) {
	f, err := security.OpenLockFile(path)
	if err != nil {
		return nil, false, errStoreUnusable.With(err, "open the lock "+filepath.Base(path))
	}
	if lockOpened != nil {
		lockOpened(path)
	}
	if shared {
		held, err = security.TryLockFileShared(f)
	} else {
		held, err = security.TryLockFile(f)
	}
	if err != nil || !held {
		f.Close()
		return nil, false, err
	}
	release = func() {
		_ = security.UnlockFile(f)
		f.Close()
	}
	// PurgeDevices may have deleted the file between the open and the lock;
	// a lock on the unlinked file excludes nobody, so it counts as not held.
	current, err := lockStillLinked(f, path)
	if err != nil || !current {
		release()
		return nil, false, err
	}
	return release, true, nil
}

// lockStillLinked reports whether path still names the open file f.
func lockStillLinked(f *os.File, path string) (bool, error) {
	held, err := f.Stat()
	if err != nil {
		return false, errStoreUnusable.With(err, "stat the lock "+filepath.Base(path))
	}
	named, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, errStoreUnusable.With(err, "stat the lock "+filepath.Base(path))
	}
	return os.SameFile(held, named), nil
}

// WaitLockFile takes the file lock at path, retrying for up to wait. It
// returns busy when the lock is still held then, and ctx.Err() when ctx ends
// first.
func WaitLockFile(ctx context.Context, path string, wait time.Duration, busy error) (func(), error) {
	return waitLockFile(ctx, path, false, wait, busy, nil)
}

// waitLockFile is WaitLockFile for a shared or exclusive lock; onAttempt,
// when set, runs after each attempt with whether it took the lock.
func waitLockFile(ctx context.Context, path string, shared bool, wait time.Duration, busy error, onAttempt func(held bool)) (func(), error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	poll := time.NewTicker(lockPollInterval)
	defer poll.Stop()
	for {
		release, held, err := tryLockFile(path, shared)
		if err != nil {
			return nil, err
		}
		if onAttempt != nil {
			onAttempt(held)
		}
		if held {
			return release, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, busy
		case <-poll.C:
		}
	}
}
