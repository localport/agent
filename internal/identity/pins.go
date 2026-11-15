package identity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	// desktopPinsFile holds the server key each desktop kind's target
	// presented and a person trusted; desktopPinsLockFile serializes its
	// writers across processes.
	desktopPinsFile     = "desktop_pins.json"
	desktopPinsLockFile = ".pins.lock"
	// pinsLockWait bounds the wait for .pins.lock. Its holders do file I/O
	// only.
	pinsLockWait = 10 * time.Second
)

// ErrDesktopPinsUnreadable wraps every refusal to read desktop_pins.json: an
// untrusted directory, a file that is not an owner-only regular file of this
// user, or content that fails to decode or validate. It is never read as an
// empty set: a pin that cannot be read refuses the connection.
var ErrDesktopPinsUnreadable = errcode.New(errcode.DesktopPinsUnreadable)

// ErrDesktopPinsBusy means another process held .pins.lock for longer than
// pinsLockWait.
var ErrDesktopPinsBusy = errcode.New(errcode.DesktopPinsBusy)

// PinResult is how Pin left a presented desktop server key.
type PinResult int

const (
	// PinNew: no pin was held for the kind's target; the key is now pinned.
	PinNew PinResult = iota + 1
	// PinMatch: the key is the pinned one.
	PinMatch
	// PinChanged: another key is pinned for the target; nothing was written.
	PinChanged
)

// desktopPin is one kind's pinned target and key.
type desktopPin struct {
	Target    string `json:"target"`
	KeySHA256 string `json:"key_sha256"`
}

// DesktopPins is a device identity's pinned desktop target keys, kept in
// desktop_pins.json beside meta.json, keyed by desktop kind ("rdp": the SHA-256
// of the leaf certificate's SPKI; "vnc": of the RA2ne key), each naming the
// target address it was pinned for. Writers hold writeMu, then the file lock
// .pins.lock, and re-read the file under both, so writers in this process and
// in others (`localport set --rdp-reset-pin`, `--vnc-reset-pin`) never lose a
// write. .pins.lock is taken alone, never with .renew.lock or .keys.lock, and
// is held across file I/O only. The file goes with the identity directory
// (Store.Remove, Store.RemoveDevices), which is never recreated here.
//
// Obtain it with Store.DesktopPins; each Store holds one instance per
// identity directory.
type DesktopPins struct {
	store *Store
	dir   string
	// writeMu queues this process's writers, so they wait on it instead of
	// polling .pins.lock.
	writeMu sync.Mutex
	// afterRead, when set, runs in update between the read and the write.
	// Tests hold a writer there.
	afterRead func()
}

// DesktopPins returns the device identity's pin store, the same instance on
// every call to this Store. A ref that is not a valid device identity returns
// ErrNotDeviceIdentity.
func (s *Store) DesktopPins(ref Ref) (*DesktopPins, error) {
	if ref.Kind != KindDevice || !ref.valid() {
		return nil, fmt.Errorf("%w: %s", ErrNotDeviceIdentity, security.SanitizeDisplay(ref.String()))
	}
	dir := s.dir(ref)
	s.ticketKeysMu.Lock()
	defer s.ticketKeysMu.Unlock()
	if p, ok := s.desktopPins[dir]; ok {
		return p, nil
	}
	if s.desktopPins == nil {
		s.desktopPins = make(map[string]*DesktopPins)
	}
	p := &DesktopPins{store: s, dir: dir}
	s.desktopPins[dir] = p
	return p, nil
}

// Lookup returns the key pinned for kind at target; held is false when none
// is pinned, or the pin names another target.
func (p *DesktopPins) Lookup(kind, target string) (key [32]byte, held bool, err error) {
	pins, _, err := p.read()
	if err != nil {
		return key, false, err
	}
	pin, ok := pins[kind]
	if !ok || pin.Target != target {
		return key, false, nil
	}
	b, _ := hex.DecodeString(pin.KeySHA256) // validated by read
	copy(key[:], b)
	return key, true, nil
}

// Pin pins key for kind at target unless a pin for that target is held, and
// reports how the key compares. A pin for another target is replaced. ctx
// bounds the wait for another writer.
func (p *DesktopPins) Pin(ctx context.Context, kind, target string, key [32]byte) (PinResult, error) {
	if kind == "" || target == "" {
		return 0, ErrDesktopPinsUnreadable.With(nil, "a pin needs a kind and a target")
	}
	var result PinResult
	err := p.update(ctx, func(pins map[string]desktopPin) bool {
		sum := hex.EncodeToString(key[:])
		if pin, ok := pins[kind]; ok && pin.Target == target {
			result = PinChanged
			if pin.KeySHA256 == sum {
				result = PinMatch
			}
			return false
		}
		pins[kind] = desktopPin{Target: target, KeySHA256: sum}
		result = PinNew
		return true
	})
	return result, err
}

// ResetResult is what Reset did.
type ResetResult int

const (
	// ResetNone: no pin was held for the kind.
	ResetNone ResetResult = iota + 1
	// ResetForgot: the kind's pin was removed.
	ResetForgot
	// ResetDiscarded: the file was unreadable and was removed with every
	// kind's pin, which it already refused.
	ResetDiscarded
)

// Reset removes kind's pin; the next connection asks on first use again. A
// pin file that fails to read or validate is removed whole, since every pin
// in it is refused anyway; an untrusted directory is never touched.
func (p *DesktopPins) Reset(ctx context.Context, kind string) (ResetResult, error) {
	result := ResetNone
	discarded, err := p.updateOrDiscard(ctx, true, func(pins map[string]desktopPin) bool {
		if _, held := pins[kind]; held {
			result = ResetForgot
		}
		delete(pins, kind)
		return result == ResetForgot
	})
	if discarded {
		result = ResetDiscarded
	}
	return result, err
}

// update runs change on the pins read under writeMu and .pins.lock and
// writes them when change reports a change.
func (p *DesktopPins) update(ctx context.Context, change func(map[string]desktopPin) bool) error {
	_, err := p.updateOrDiscard(ctx, false, change)
	return err
}

// updateOrDiscard is update; with discard set, a pin file in a trusted
// directory that fails to read is removed under the locks and change runs on
// an empty set, and discarded reports it.
func (p *DesktopPins) updateOrDiscard(ctx context.Context, discard bool, change func(map[string]desktopPin) bool) (discarded bool, err error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	release, err := WaitLockFile(ctx, filepath.Join(p.dir, desktopPinsLockFile), pinsLockWait, ErrDesktopPinsBusy)
	if err != nil {
		return false, err
	}
	defer release()
	pins, dirTrusted, err := p.read()
	if p.afterRead != nil {
		p.afterRead()
	}
	if err != nil {
		if !discard || !dirTrusted {
			return false, err
		}
		if rmErr := removeSharedFile(ctx, filepath.Join(p.dir, desktopPinsFile), pinsLockWait); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return false, fmt.Errorf("%w: remove: %w", err, rmErr)
		}
		pins, discarded = map[string]desktopPin{}, true
	}
	if !change(pins) {
		return discarded, nil
	}
	return discarded, p.write(pins)
}

// removeSharedFile removes path, retrying a Windows sharing violation (another
// process holds the file open without delete sharing) every lockPollInterval
// for up to wait. Other errors return at once.
func removeSharedFile(ctx context.Context, path string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := os.Remove(path)
		if !isSharingViolation(err) || time.Now().Add(lockPollInterval).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(lockPollInterval):
		}
	}
}

// read returns the validated pins; an absent file is an empty set. The
// directory passes the same trust checks as the credential's; dirTrusted
// reports that check, so a caller deciding on the file acts on the same
// result.
func (p *DesktopPins) read() (pins map[string]desktopPin, dirTrusted bool, err error) {
	if err := p.store.trusted(p.dir); err != nil {
		return nil, false, ErrDesktopPinsUnreadable.With(err, "")
	}
	raw, err := security.ReadPrivateFile(filepath.Join(p.dir, desktopPinsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]desktopPin{}, true, nil
	}
	if err != nil {
		return nil, true, ErrDesktopPinsUnreadable.With(err, "")
	}
	pins = map[string]desktopPin{}
	if err := json.Unmarshal(raw, &pins); err != nil {
		return nil, true, ErrDesktopPinsUnreadable.With(err, "parse")
	}
	for kind, pin := range pins {
		if b, err := hex.DecodeString(pin.KeySHA256); err != nil || len(b) != 32 || kind == "" || pin.Target == "" {
			return nil, true, ErrDesktopPinsUnreadable.With(nil, fmt.Sprintf("invalid pin for %q", security.SanitizeDisplay(kind)))
		}
	}
	return pins, true, nil
}

func (p *DesktopPins) write(pins map[string]desktopPin) error {
	raw, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return fmt.Errorf("encode desktop pins: %w", err)
	}
	if err := security.WritePrivateFileAtomic(filepath.Join(p.dir, desktopPinsFile), raw); err != nil {
		return fmt.Errorf("write desktop pins: %w", err)
	}
	return nil
}
