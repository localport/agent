package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

// ErrTicketKeysBusy means another process held the identity's key lock for
// longer than keysLockWait.
var ErrTicketKeysBusy = errcode.New(errcode.TicketKeysBusy)

// ErrTicketKeysUnreadable wraps every refusal to read ticket_keys.json: an
// untrusted directory, a file that is not an owner-only regular file of this
// user, or content that fails to decode or validate.
var ErrTicketKeysUnreadable = errcode.New(errcode.TicketKeysUnreadable)

// ErrRecordingKeyDropped means Load found a recording key in ticket_keys.json
// that does not parse: the ticket keys loaded, the recording key was skipped,
// and the next Replace (key fetch or renewal) writes a valid one.
var ErrRecordingKeyDropped = errors.New("the stored team recording key does not parse and was skipped")

// keysLockWait bounds the wait for .keys.lock. Its holders do file I/O only.
const keysLockWait = 10 * time.Second

// ticketKIDPattern is the kid grammar of the control plane's ticket keys.
var ticketKIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// ErrNotDeviceIdentity means a ticket key store was asked for a ref that is
// not a valid device identity; only devices hold ticket keys.
var ErrNotDeviceIdentity = errors.New("only a device identity holds ticket keys")

// TicketKeys is a device identity's session ticket verification keys and its
// team's recording key, kept in ticket_keys.json beside meta.json. Only the
// control plane changes the stored set (Replace, from enrolment, renewal and
// KeyRefresher's fetch); a kid absent from its set is revoked.
//
// The edge names kids it saw revoked in each RegisterAck. The edge relays them
// without authority over the key set, so they are hints kept in memory only
// (Hint): a hinted kid is refused until a set the control plane sent after
// the hint settles it, or for at most suspectTTL. Ordering uses a generation
// counter: a caller reads Generation before its request, and Replace settles
// only the hints given at or before that generation.
//
// Writers hold writeMu, then the file lock .keys.lock, and re-read the file
// under both, so writers in this process and in others never lose a write.
// A caller holding .renew.lock may take the key lock; nothing holding the key
// lock takes .renew.lock. The key lock is never held across network I/O: its
// holders do file I/O only.
//
// Obtain it with Store.TicketKeys; each Store holds one instance per identity
// directory, so a process shares locks and memory only through one Store.
type TicketKeys struct {
	store *Store
	dir   string

	// writeMu queues this process's writers, so they wait on it instead of
	// polling .keys.lock every lockPollInterval toward the keysLockWait bound.
	writeMu sync.Mutex

	// mu guards the in-memory view below. It is never held across I/O.
	mu           sync.RWMutex
	keys         map[string]ed25519.PublicKey
	recordingKey heldRecordingKey
	suspects     map[string]suspect
	generation   uint64
	// now replaces time.Now. Tests set it.
	now func() time.Time

	// afterRead, when set, runs after Load or a writer has read the file and
	// before it writes or publishes. Tests hold one there.
	afterRead func()
}

// ticketKeysRecord is ticket_keys.json.
type ticketKeysRecord struct {
	Keys         []TicketKey `json:"keys"`
	RecordingKey string      `json:"recording_key"`
}

// A suspect is a held kid the edge named revoked: when it was last hinted and
// the generation of that hint.
type suspect struct {
	at         time.Time
	generation uint64
}

const (
	// suspectTTL bounds how long a hint refuses a kid when no control plane
	// set settles it, as while the control plane is unreachable.
	suspectTTL = 15 * time.Minute
	// maxSuspects bounds the hints held; the oldest is dropped first.
	maxSuspects = 64
)

// heldRecordingKey is the decoded team recording public key and its SHA-256;
// raw is nil when no key is held.
type heldRecordingKey struct {
	raw []byte
	sum [sha256.Size]byte
}

// TicketKeys returns the device identity's key store, the same instance on
// every call to this Store. It does no I/O; call Load to read the file. A ref
// that is not a valid device identity returns ErrNotDeviceIdentity.
func (s *Store) TicketKeys(ref Ref) (*TicketKeys, error) {
	if ref.Kind != KindDevice || !ref.valid() {
		return nil, fmt.Errorf("%w: %s", ErrNotDeviceIdentity, security.SanitizeDisplay(ref.String()))
	}
	dir := s.dir(ref)
	s.ticketKeysMu.Lock()
	defer s.ticketKeysMu.Unlock()
	if tk, ok := s.ticketKeys[dir]; ok {
		return tk, nil
	}
	if s.ticketKeys == nil {
		s.ticketKeys = make(map[string]*TicketKeys)
	}
	tk := &TicketKeys{
		store:    s,
		dir:      dir,
		keys:     map[string]ed25519.PublicKey{},
		suspects: map[string]suspect{},
		now:      time.Now,
	}
	s.ticketKeys[dir] = tk
	return tk, nil
}

// Path is the identity's ticket_keys.json.
func (t *TicketKeys) Path() string { return filepath.Join(t.dir, ticketKeysFile) }

// forgetTicketKeys drops the ticket key and desktop pin instances of a
// removed identity directory, so a later enrolment into the same directory
// starts from its files.
func (s *Store) forgetTicketKeys(dir string) {
	s.ticketKeysMu.Lock()
	defer s.ticketKeysMu.Unlock()
	delete(s.ticketKeys, dir)
	delete(s.desktopPins, dir)
}

// Load reads ticket_keys.json into memory. An absent file is an empty set; a
// file it cannot read returns ErrTicketKeysUnreadable and leaves memory
// unchanged. A recording key that does not parse is skipped: the ticket keys
// load, the recording key held before (if any) stays, and Load returns
// ErrRecordingKeyDropped for the caller to log.
func (t *TicketKeys) Load() error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, pubs, recKey, err := t.read()
	dropped := errors.Is(err, ErrRecordingKeyDropped)
	if err != nil && !dropped {
		return err
	}
	if t.afterRead != nil {
		t.afterRead()
	}
	t.mu.Lock()
	if dropped {
		recKey = t.recordingKey
	}
	t.publishLocked(pubs, recKey)
	t.mu.Unlock()
	return err
}

// RecordingKey returns a copy of the team recording public key (the bytes of
// an X-Wing hpke.PublicKey) and its SHA-256. ok is false when no key is held.
// It reads memory only and is safe for concurrent use.
func (t *TicketKeys) RecordingKey() (key []byte, sum [sha256.Size]byte, ok bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.recordingKey.raw == nil {
		return nil, sum, false
	}
	return slices.Clone(t.recordingKey.raw), t.recordingKey.sum, true
}

// Lookup returns the verification key for kid; a kid under a live hint is
// refused. It reads memory only and is safe for concurrent use.
func (t *TicketKeys) Lookup(kid string) (ed25519.PublicKey, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if s, hinted := t.suspects[kid]; hinted && t.now().Sub(s.at) < suspectTTL {
		return nil, false
	}
	pub, ok := t.keys[kid]
	return pub, ok
}

// CAKeys returns the session CA keys that sign SSH user certificates: every
// held key whose kid is not under a live hint. It reads memory only and is
// safe for concurrent use.
func (t *TicketKeys) CAKeys() []ed25519.PublicKey {
	t.mu.RLock()
	defer t.mu.RUnlock()
	now := t.now()
	keys := make([]ed25519.PublicKey, 0, len(t.keys))
	for kid, pub := range t.keys {
		if s, hinted := t.suspects[kid]; hinted && now.Sub(s.at) < suspectTTL {
			continue
		}
		keys = append(keys, pub)
	}
	return keys
}

// Generation returns the hint generation. Read it before a request whose key
// set is passed to Replace.
func (t *TicketKeys) Generation() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.generation
}

// Hint records kids the edge named revoked. A kid not in the held set is
// ignored. added reports whether a held kid is now under a hint, which the
// caller answers with a key fetch. A malformed kid refuses the whole list.
func (t *TicketKeys) Hint(kids []string) (added bool, err error) {
	for _, kid := range kids {
		if !ticketKIDPattern.MatchString(kid) {
			return false, fmt.Errorf("revoked ticket kid %q is not a kid", security.SanitizeDisplay(kid))
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.generation++
	for _, kid := range kids {
		if _, held := t.keys[kid]; !held {
			continue
		}
		t.suspects[kid] = suspect{at: now, generation: t.generation}
		added = true
	}
	for len(t.suspects) > maxSuspects {
		oldest := ""
		for kid, s := range t.suspects {
			if oldest == "" || s.at.Before(t.suspects[oldest].at) {
				oldest = kid
			}
		}
		delete(t.suspects, oldest)
	}
	return added, nil
}

// Replace makes set the identity's key set and recording key and settles the
// hints given at or before generation, which the caller read before it
// requested set. It never merges: a kid absent from set leaves. A set with an
// unusable ticket key or recording key is refused whole and the held set and
// key stay. ctx bounds the wait for another writer.
func (t *TicketKeys) Replace(ctx context.Context, generation uint64, set DeviceKeys) error {
	if _, err := parseTicketKeys(set.TicketKeys); err != nil {
		return fmt.Errorf("control plane sent unusable ticket keys: %w", err)
	}
	if _, err := parseRecordingKey(set.RecordingKey); err != nil {
		return fmt.Errorf("control plane sent an unusable recording key: %w", err)
	}
	rec := ticketKeysRecord{Keys: set.TicketKeys, RecordingKey: set.RecordingKey}
	if rec.Keys == nil {
		rec.Keys = []TicketKey{}
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	release, err := waitLockFile(ctx, filepath.Join(t.dir, ticketKeysLockFile), keysLockWait, ErrTicketKeysBusy)
	if err != nil {
		return err
	}
	defer release()

	// A dropped recording key is what this write repairs.
	cur, _, _, err := t.read()
	if err != nil && !errors.Is(err, ErrRecordingKeyDropped) {
		return err
	}
	if t.afterRead != nil {
		t.afterRead()
	}
	pubs, err := parseTicketKeys(rec.Keys)
	if err != nil {
		return err
	}
	recKey, err := parseRecordingKey(rec.RecordingKey)
	if err != nil {
		return err
	}
	if !sameRecord(cur, rec) {
		if err := writeTicketKeys(t.dir, rec); err != nil {
			return err
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.publishLocked(pubs, recKey)
	for kid, s := range t.suspects {
		if _, held := pubs[kid]; !held || s.generation <= generation {
			delete(t.suspects, kid)
		}
	}
	return nil
}

// publishLocked makes pubs and recKey the in-memory view. The caller holds mu.
func (t *TicketKeys) publishLocked(pubs map[string]ed25519.PublicKey, recKey heldRecordingKey) {
	t.keys = pubs
	t.recordingKey = recKey
}

// read returns the validated file and its decoded keys; an absent file is an
// empty record with no recording key. The directory passes the same trust
// checks as the credential's. Every refusal wraps ErrTicketKeysUnreadable. A
// recording key that does not parse is not a refusal: the record and ticket
// keys come back with no recording key and an error wrapping
// ErrRecordingKeyDropped.
func (t *TicketKeys) read() (ticketKeysRecord, map[string]ed25519.PublicKey, heldRecordingKey, error) {
	if err := t.store.trusted(t.dir); err != nil {
		return ticketKeysRecord{}, nil, heldRecordingKey{}, fmt.Errorf("%w: %w", ErrTicketKeysUnreadable, err)
	}
	raw, err := security.ReadPrivateFile(filepath.Join(t.dir, ticketKeysFile))
	if errors.Is(err, fs.ErrNotExist) {
		return ticketKeysRecord{}, map[string]ed25519.PublicKey{}, heldRecordingKey{}, nil
	}
	if err != nil {
		return ticketKeysRecord{}, nil, heldRecordingKey{}, fmt.Errorf("%w: %w", ErrTicketKeysUnreadable, err)
	}
	var rec ticketKeysRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return ticketKeysRecord{}, nil, heldRecordingKey{}, fmt.Errorf("%w: parse: %w", ErrTicketKeysUnreadable, err)
	}
	pubs, err := parseTicketKeys(rec.Keys)
	if err != nil {
		return ticketKeysRecord{}, nil, heldRecordingKey{}, fmt.Errorf("%w: %w", ErrTicketKeysUnreadable, err)
	}
	recKey, err := parseRecordingKey(rec.RecordingKey)
	if err != nil {
		return rec, pubs, heldRecordingKey{}, fmt.Errorf("%w: %w", ErrRecordingKeyDropped, err)
	}
	return rec, pubs, recKey, nil
}

func writeTicketKeys(dir string, rec ticketKeysRecord) error {
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ticket keys: %w", err)
	}
	return security.WritePrivateFileAtomic(filepath.Join(dir, ticketKeysFile), append(raw, '\n'))
}

// parseTicketKeys decodes keys and refuses a malformed kid, a public key that
// is not 32 bytes of unpadded base64url, and a duplicate kid.
func parseTicketKeys(keys []TicketKey) (map[string]ed25519.PublicKey, error) {
	pubs := make(map[string]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		if !ticketKIDPattern.MatchString(k.KID) {
			return nil, fmt.Errorf("ticket key kid %q is not a kid", security.SanitizeDisplay(k.KID))
		}
		if _, dup := pubs[k.KID]; dup {
			return nil, fmt.Errorf("ticket key kid %q appears twice", k.KID)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ticket key %q is not an Ed25519 public key", k.KID)
		}
		pubs[k.KID] = ed25519.PublicKey(raw)
	}
	return pubs, nil
}

// parseRecordingKey decodes the team recording key: unpadded base64url of an
// X-Wing (MLKEM768X25519) public key. An empty string holds no key.
func parseRecordingKey(encoded string) (heldRecordingKey, error) {
	if encoded == "" {
		return heldRecordingKey{}, nil
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return heldRecordingKey{}, errors.New("recording key is not unpadded base64url")
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(raw); err != nil {
		return heldRecordingKey{}, errors.New("recording key is not an X-Wing public key")
	}
	return heldRecordingKey{raw: raw, sum: sha256.Sum256(raw)}, nil
}

func sameRecord(a, b ticketKeysRecord) bool {
	return a.RecordingKey == b.RecordingKey && slices.Equal(a.Keys, b.Keys)
}
