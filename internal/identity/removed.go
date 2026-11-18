package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/localport/agent/internal/security"
)

// Codes the control plane and the edge refuse a device with. SE018 and SE041
// mean the device no longer exists for them, and the device forgets its
// credential on either; SE040 does not.
const (
	// CodeDeviceUnknown (SE018): the device was removed, or its fleet deleted.
	CodeDeviceUnknown = "SE018"
	// CodeDeviceCertRevoked (SE041): the certificate was revoked because the
	// device was enrolled again or removed.
	CodeDeviceCertRevoked = "SE041"
	// CodeDeviceDisabled (SE040): an admin disconnected the device. Not
	// definitive: an admin's Reconnect lifts it.
	CodeDeviceDisabled = "SE040"
)

// IsRemovalCode reports whether code tells a device it no longer exists.
func IsRemovalCode(code string) bool {
	return code == CodeDeviceUnknown || code == CodeDeviceCertRevoked
}

// RemovedError is a control plane refusal (Code SE018 or SE041) of the device
// credential with serial Serial.
type RemovedError struct {
	Code   string
	Serial string
	Err    error
}

func (e *RemovedError) Error() string { return e.Err.Error() }
func (e *RemovedError) Unwrap() error { return e.Err }

// removedError wraps err in a RemovedError when it is a removal refusal of
// the credential cur.
func removedError(err error, cur *Material) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !IsRemovalCode(apiErr.Code) {
		return err
	}
	return &RemovedError{Code: apiErr.Code, Serial: cur.Meta.Serial, Err: err}
}

// tombstoneSuffix names the file beside a device's credential directory that
// records the device was forgotten.
const tombstoneSuffix = ".removed"

// Tombstone records why and when a device credential was forgotten. It holds
// no secret.
type Tombstone struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
}

func (s *Store) tombstonePath(ref Ref) string { return s.dir(ref) + tombstoneSuffix }

// Forget deletes the device credential ref after a removal refusal of the
// certificate with serial serial, and writes its tombstone. serial matches
// the current certificate or a pending renewal of it (a registration presents
// the pending one first). When neither has that serial (a re-enrolment
// replaced the credential), nothing is deleted and Forget returns false. The
// check, the tombstone and the deletion of the whole directory run under the
// credential's renewal lock, which Save also takes before it creates the
// directory, so a concurrent enrolment is never deleted.
func (s *Store) Forget(ctx context.Context, ref Ref, code, serial string) (bool, error) {
	raw, err := json.Marshal(Tombstone{Code: code, At: time.Now().UTC()})
	if err != nil {
		return false, err
	}
	release, err := s.waitLock(ctx, ref, saveLockWait)
	if err != nil {
		return false, errStoreUnusable.With(err, "lock "+ref.String())
	}
	defer release()
	dir := s.dir(ref)
	// No credential directory (or a stray non-directory path): record the
	// removal and clear the path.
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
		cur, pending, err := s.readPair(ref)
		// An unreadable credential is deleted: no refusal leaves it usable.
		if err == nil && cur.Serial != serial && (pending == nil || pending.Serial != serial) {
			return false, nil
		}
	}
	// Written first, so a crash between the two leaves a tombstone beside a
	// credential, which the runner runs (a later refusal forgets it again),
	// never a forgotten credential without a tombstone.
	if err := s.writeTombstone(ref, raw); err != nil {
		return false, err
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, errStoreUnusable.With(err, "remove "+ref.String())
	}
	s.forgetTicketKeys(dir)
	return true, nil
}

// writeTombstone writes ref's tombstone, creating its team directory, which a
// purge may have removed with the team's last credential.
func (s *Store) writeTombstone(ref Ref, raw []byte) error {
	path := s.tombstonePath(ref)
	base, follow := s.StateRoot()
	if err := security.EnsurePrivateDir(base, filepath.Dir(path), follow); err != nil {
		return errStoreUnusable.With(err, "create the directory of the tombstone of "+ref.String())
	}
	if err := security.WritePrivateFileAtomic(path, raw); err != nil {
		return errStoreUnusable.With(err, "write the tombstone of "+ref.String())
	}
	return nil
}

// ReadTombstone returns the tombstone of ref, or nil when it has none.
func (s *Store) ReadTombstone(ref Ref) (*Tombstone, error) {
	raw, err := security.ReadPrivateFile(s.tombstonePath(ref))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errUnreadable.With(err, ref.String()+tombstoneSuffix)
	}
	var t Tombstone
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, errUnreadable.With(fmt.Errorf("decode tombstone: %w", err), ref.String()+tombstoneSuffix)
	}
	return &t, nil
}

// DeleteTombstone removes the tombstone of ref; a missing one is not an error.
func (s *Store) DeleteTombstone(ref Ref) error {
	if err := os.Remove(s.tombstonePath(ref)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errStoreUnusable.With(err, "remove the tombstone of "+ref.String())
	}
	return nil
}

// Tombstones lists the device refs that hold a tombstone. A file whose name
// is not a valid device ref is skipped.
func (s *Store) Tombstones() ([]Ref, error) {
	matches, err := filepath.Glob(filepath.Join(s.Root, "*", string(KindDevice)+"-*"+tombstoneSuffix))
	if err != nil {
		return nil, fmt.Errorf("read identity store: %w", err)
	}
	refs := make([]Ref, 0, len(matches))
	for _, path := range matches {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), string(KindDevice)+"-"), tombstoneSuffix)
		ref, err := ParseDeviceRef(filepath.Base(filepath.Dir(path)) + "/" + string(KindDevice) + "/" + name)
		if err != nil {
			continue
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
