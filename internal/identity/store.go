// Package identity obtains, stores and renews the machine's mTLS credentials
// (setup token, sign-in, device join token).
//
// A machine redeems each token once. The private key stays on the machine,
// and the current certificate authorizes each renewal.
package identity

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	metaFile = "meta.json"
	// pendingFile commits a renewed device credential that has not yet been
	// registered with. meta.json keeps naming the current one until Promote.
	pendingFile = "pending.json"
	lockFile    = ".renew.lock"
	// ticketKeysFile holds a device's session CA keys and team recording
	// key; ticketKeysLockFile serializes its writers across processes.
	ticketKeysFile     = "ticket_keys.json"
	ticketKeysLockFile = ".keys.lock"
	// storeLockFile in Root is held shared by every holder of a credential
	// lock and exclusively by PurgeDevices.
	storeLockFile = ".store.lock"
)

// LocksDir under a store's Root holds every credential's lock directory. Team
// names start with an alphanumeric (validRefComponent), so it never collides
// with a team directory. Only PurgeDevices deletes it.
const LocksDir = ".locks"

// Source is how a credential was obtained. Values are persisted in meta.json
// and must not change meaning.
type Source string

const (
	SourceToken Source = "token" // setup or join token, renews itself
	SourceOIDC  Source = "oidc"  // CI workload identity, held in memory
	SourceSSO   Source = "sso"   // `localport login`, short-lived, for a person
)

// Renewable reports whether a credential from this source can be reissued.
// Only a token credential renews. A sign-in does not, the user signs in
// again; a workload credential does not, the job mints a fresh identity
// token. Unknown sources are not renewable.
func (s Source) Renewable() bool { return s == SourceToken }

// Valid reports whether s is a source this build knows how to act on.
func (s Source) Valid() bool {
	switch s {
	case SourceToken, SourceOIDC, SourceSSO:
		return true
	default:
		return false
	}
}

// Meta is the metadata stored next to the key material. APIURL records the
// issuing control plane for renewal. Source distinguishes a sign-in from a
// setup token and decides renewal.
type Meta struct {
	Identity string `json:"identity"`
	Team     string `json:"team"`
	// TeamName is the display name in `localport identity list`. It is
	// optional and refreshed on renewal. Team is the key.
	TeamName string `json:"team_name,omitempty"`
	Kind     Kind   `json:"kind"`
	SpiffeID string `json:"spiffe_id"`
	Key      KeyRef `json:"key"`

	// Cert is the certificate file name next to Key.File. Both files are
	// written before meta.json, which commits the pair.
	Cert string `json:"cert"`

	Source   Source    `json:"source"`
	APIURL   string    `json:"api_url"`
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`

	// RenewAfter is nil when the credential does not renew. A zero time would
	// serialize as a real past date. Read it through NextRenewal.
	RenewAfter *time.Time `json:"renew_after,omitempty"`

	UpdatedAt time.Time `json:"updated_at"`

	// Device is set for a device credential only: what enrolment reported
	// besides the certificate.
	Device *DeviceInfo `json:"device,omitempty"`

	// RenewedFrom is set in pending.json only: the serial of the current
	// credential the renewal started from. A pending credential whose parent
	// is no longer current is ignored.
	RenewedFrom string `json:"renewed_from,omitempty"`
}

// NextRenewal returns the renewal time and whether the credential renews. The
// result is false when RenewAfter is nil or the source does not renew.
func (m Meta) NextRenewal() (time.Time, bool) {
	if !m.Source.Renewable() || m.RenewAfter == nil {
		return time.Time{}, false
	}
	return *m.RenewAfter, true
}

// Material is one stored credential, the presented certificate chain, its
// private key and its metadata.
type Material struct {
	CertPEM []byte // leaf first, then the issuing chain
	Key     Key
	Meta    Meta

	// DeviceKeys is the key set a device enrolment or renewal response
	// carried; nil otherwise. The Store's credential writes ignore it: the
	// enrolling caller (cli up) and Renewer pass it to TicketKeys.Replace
	// after the credential is stored. It is never written to meta.json or
	// pending.json.
	DeviceKeys *DeviceKeys
}

// Store is a directory of credentials, one subdirectory per Ref.
type Store struct {
	Root string
	// Base is where the security.EnsurePrivateDir walk starts, "" means Root.
	// BaseChosen allows Base to be a symlink. True for LOCALPORT_HOME and
	// $HOME, false for the system-wide default.
	Base       string
	BaseChosen bool

	// ticketKeys holds one TicketKeys per credential directory, so every
	// caller of this Store shares its locks and memory. Another Store on the
	// same Root gets instances of its own.
	ticketKeysMu sync.Mutex
	ticketKeys   map[string]*TicketKeys
	// desktopPins holds one DesktopPins per device directory, as ticketKeys;
	// guarded by ticketKeysMu.
	desktopPins map[string]*DesktopPins

	// afterMetaRead, when set, runs in readPair between its two reads. Tests
	// promote there.
	afterMetaRead func()
	// renewLockAttempt, when set, runs after each waitLockAt attempt with
	// whether it took the renewal lock. Tests interleave writers there.
	renewLockAttempt func(held bool)
	// renewLockReleasing, when set, runs just before a waitLockAt holder
	// releases the renewal lock. Tests check what was done under it.
	renewLockReleasing func()
	// storeLockReleasing, when set, runs just before PurgeDevices releases the
	// store lock; storeShareAttempt runs after each attempt to take it
	// shared, with whether it was taken.
	storeLockReleasing func()
	storeShareAttempt  func(held bool)
}

// HomeEnv overrides where credentials live.
const HomeEnv = "LOCALPORT_HOME"

// DefaultStore is the store of an unprivileged process:
// $LOCALPORT_HOME/identity, or ~/.localport/identity.
func DefaultStore() (*Store, error) {
	root, chosen, err := defaultRoot()
	if err != nil {
		return nil, err
	}
	return &Store{Root: filepath.Join(root, "identity"), Base: root, BaseChosen: chosen}, nil
}

// SystemStore is the store of the device service: <dir>/identity, where dir is
// the machine-wide config directory. LOCALPORT_HOME is ignored and nothing is
// followed as a symlink. The identity directory belongs to the agent account
// (on Windows the device service's SID) inside the system-owned dir, so it
// is its own walk base and the recording spool lands in it.
func SystemStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("system credential directory \"%s\" is not absolute", security.SanitizeDisplay(dir))
	}
	root := filepath.Join(dir, "identity")
	return &Store{Root: root, Base: root}, nil
}

// EnsureRoot creates the store directory owner-only when missing and refuses
// one that fails the private directory walk. up, setup and login run it
// before spending their one-time secret.
func (s *Store) EnsureRoot() error {
	base, follow := s.StateRoot()
	if err := security.EnsurePrivateDir(base, s.Root, follow); err != nil {
		return errStoreUnusable.With(err, s.Root)
	}
	return nil
}

// ErrDeviceCredential refuses a fleet device's credential where a consumer
// credential is required: access, setup and login.
var ErrDeviceCredential = errcode.New(errcode.DeviceCredential)

var (
	// errUnreadable is a stored credential that cannot be read or used.
	errUnreadable = errcode.New(errcode.CredentialUnreadable)
	// errStoreUnusable is a store directory that cannot be created, read
	// or changed.
	errStoreUnusable = errcode.New(errcode.CredentialStoreUnusable)
)

// defaultRoot returns the base directory of an unprivileged process,
// LOCALPORT_HOME or ~/.localport, and true: both are chosen by the user, so
// the base may be a symlink. There is no machine-wide fallback: a privileged
// process uses SystemStore, and a machine-wide directory for an unprivileged
// one would name the privileged root on case-insensitive file systems.
func defaultRoot() (string, bool, error) {
	if v := strings.TrimSpace(os.Getenv(HomeEnv)); v != "" {
		return v, true, nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".localport"), true, nil
	}
	return "", false, errStoreUnusable.With(nil, "no home directory to hold it; set "+HomeEnv)
}

// StateRoot returns the state root, where the private directory walk of the
// store and of state kept beside it starts, and whether it may be a symlink.
// An empty Base means Root, which may be a symlink.
func (s *Store) StateRoot() (string, bool) {
	if s.Base == "" {
		return s.Root, true
	}
	return s.Base, s.BaseChosen
}

func (s *Store) dir(ref Ref) string { return filepath.Join(s.Root, ref.Path()) }

// Skipped is a credential directory List could not read. `identity list`
// prints these so they are not mistaken for missing credentials.
type Skipped struct {
	Path   string
	Reason error
}

// List returns every stored credential, sorted. The Ref is read from meta.json
// rather than decoded back out of the path, so the directory names stay purely
// a legibility aid.
func (s *Store) List() ([]Ref, error) {
	refs, _, err := s.ListWithSkipped()
	return refs, err
}

// ListWithSkipped is List plus what it could not read.
func (s *Store) ListWithSkipped() ([]Ref, []Skipped, error) {
	matches, err := filepath.Glob(filepath.Join(s.Root, "*", "*", metaFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read identity store: %w", err)
	}
	refs := make([]Ref, 0, len(matches))
	var skipped []Skipped
	for _, path := range matches {
		// Only `<team>/<kind>-<identity>` holds a credential; the recording
		// spool's `recordings/<uuid>/meta.json` shares the glob.
		kind, _, ok := strings.Cut(filepath.Base(filepath.Dir(path)), "-")
		if !ok || !Kind(kind).Valid() {
			continue
		}
		if err := s.trusted(filepath.Dir(path)); err != nil {
			skipped = append(skipped, Skipped{Path: filepath.Dir(path), Reason: err})
			continue
		}
		meta, err := readMeta(path)
		if err != nil {
			skipped = append(skipped, Skipped{Path: filepath.Dir(path), Reason: err})
			continue
		}
		ref, err := refFromMeta(meta)
		if err != nil {
			skipped = append(skipped, Skipped{Path: filepath.Dir(path), Reason: err})
			continue
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].dir() < refs[j].dir() })
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return refs, skipped, nil
}

// Remove deletes a credential's directory. Local only: the certificate stays
// valid until it is revoked. Callers must say so, or an operator reads the
// deletion as a withdrawal of access.
func (s *Store) Remove(ctx context.Context, ref Ref) error {
	dir := s.dir(ref)
	if _, err := os.Stat(dir); err != nil {
		return errUnreadable.With(err, ref.String())
	}
	if err := s.removeCredential(ctx, ref); err != nil {
		return errStoreUnusable.With(err, "remove "+ref.String())
	}
	s.forgetTicketKeys(dir)
	return nil
}

// removeCredential deletes ref's credential directory while holding its
// renewal lock, waiting up to saveLockWait for a renewal in flight. The lock
// lives in the lock directory, so the whole credential directory goes under it
// and a Save waiting on the lock creates the directory afresh. A path that is
// not a real directory (a symlink) is removed itself, never followed.
func (s *Store) removeCredential(ctx context.Context, ref Ref) error {
	release, err := s.waitLock(ctx, ref, saveLockWait)
	if err != nil {
		return err
	}
	defer release()
	return os.RemoveAll(s.dir(ref))
}

// PurgeDevices deletes every device credential directory and tombstone,
// readable or not, then calls also, and returns the deleted paths. Other
// credentials and their team directories stay. It first takes the store lock
// exclusively, waiting up to saveLockWait for the holders of credential locks
// to release their shared holds (ErrRenewalInProgress), so no credential lock
// is held or awaited while it runs. Under that hold it deletes the lock directory and, when Root then holds
// nothing else, the store lock file itself, so an emptied Root can be removed.
// Purges never overlap (the one caller, `service uninstall --purge`, holds
// run.lock and agent.yaml.lock) and every other holder takes the store lock
// shared. A holder that opened the store lock before its deletion finds the
// path no longer names its file once locked, and opens it again.
// A missing Root is left missing and only also is called. Local only, as
// Remove.
func (s *Store) PurgeDevices(ctx context.Context, also func() error) ([]string, error) {
	if _, err := os.Lstat(s.Root); errors.Is(err, fs.ErrNotExist) {
		if also != nil {
			return nil, also()
		}
		return nil, nil
	}
	path, err := s.storeLockPath()
	if err != nil {
		return nil, err
	}
	release, err := waitLockFile(ctx, path, false, saveLockWait, ErrRenewalInProgress, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if s.storeLockReleasing != nil {
			s.storeLockReleasing()
		}
		release()
	}()
	paths, err := filepath.Glob(filepath.Join(s.Root, "*", string(KindDevice)+"-*"))
	if err != nil {
		return nil, fmt.Errorf("read identity store: %w", err)
	}
	for i, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			return paths[:i], errStoreUnusable.With(err, "remove "+p)
		}
		s.forgetTicketKeys(p)
	}
	if also != nil {
		if err := also(); err != nil {
			return paths, err
		}
	}
	if err := os.RemoveAll(filepath.Join(s.Root, LocksDir)); err != nil {
		return paths, errStoreUnusable.With(err, "remove the lock directory")
	}
	left, err := os.ReadDir(s.Root)
	if err != nil {
		return paths, errStoreUnusable.With(err, "read "+s.Root)
	}
	if len(left) == 1 && left[0].Name() == storeLockFile {
		if err := os.Remove(path); err != nil {
			return paths, errStoreUnusable.With(err, "remove the store lock")
		}
	}
	return paths, nil
}

// storeLockPath creates Root and returns the path of the store lock: every
// holder of a credential lock holds it shared, and PurgeDevices holds it
// exclusively.
func (s *Store) storeLockPath() (string, error) {
	if err := s.EnsureRoot(); err != nil {
		return "", err
	}
	return filepath.Join(s.Root, storeLockFile), nil
}

// ErrStoreBusy means PurgeDevices holds the store lock.
var ErrStoreBusy = errcode.New(errcode.StoreBusy)

// shareStore takes the store lock shared, waiting up to wait, and returns
// ErrStoreBusy when a purge still holds it then.
func (s *Store) shareStore(ctx context.Context, wait time.Duration) (func(), error) {
	path, err := s.storeLockPath()
	if err != nil {
		return nil, err
	}
	return waitLockFile(ctx, path, true, wait, ErrStoreBusy, s.storeShareAttempt)
}

// tryShareStore is shareStore without waiting.
func (s *Store) tryShareStore() (func(), error) {
	path, err := s.storeLockPath()
	if err != nil {
		return nil, err
	}
	release, held, err := tryLockFile(path, true)
	if err == nil && !held {
		err = ErrStoreBusy
	}
	return release, err
}

// ShareStore takes the store lock shared, waiting up to saveLockWait, for a
// caller that keeps a lock file in LockDir: it holds the returned hold for as
// long as it holds that lock. It returns ErrStoreBusy while a purge runs past
// the wait.
func (s *Store) ShareStore(ctx context.Context) (func(), error) {
	return s.shareStore(ctx, saveLockWait)
}

// LockDir creates ref's lock directory and returns its path. Every lock file
// of the credential (renewal, ticket keys, desktop pins, sessions) lives there
// rather than in the credential directory, and is held only under a shared
// hold of the store lock (ShareStore). A lock file is never deleted while a
// holder could have it open: only PurgeDevices deletes the lock directory,
// holding the store lock exclusively.
func (s *Store) LockDir(ref Ref) (string, error) { return s.lockDirAt(ref.Path()) }

// lockDirAt creates the lock directory of the credential at rel, a path
// relative to Root, and returns it. The directory is named by the SHA-256 of
// rel in slash form, so the lock files left behind after a credential is
// deleted name no team or device.
func (s *Store) lockDirAt(rel string) (string, error) {
	sum := sha256.Sum256([]byte(filepath.ToSlash(rel)))
	dir := filepath.Join(s.Root, LocksDir, hex.EncodeToString(sum[:]))
	base, follow := s.StateRoot()
	if err := security.EnsurePrivateDir(base, dir, follow); err != nil {
		return "", errStoreUnusable.With(err, "create the lock directory "+dir)
	}
	return dir, nil
}

// lockFileAt creates the lock directory of the credential at rel and returns
// the path of its lock file name.
func (s *Store) lockFileAt(rel, name string) (string, error) {
	dir, err := s.lockDirAt(rel)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

// Resolve returns the one credential a selector names. An ambiguous selector
// is an error.
func (s *Store) Resolve(sel Selector) (Ref, error) {
	all, err := s.List()
	if err != nil {
		return Ref{}, err
	}
	return resolveIn(sel, all)
}

// ListConsumers is List without device credentials: what access may present.
func (s *Store) ListConsumers() ([]Ref, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	consumers := all[:0]
	for _, ref := range all {
		if ref.Kind != KindDevice {
			consumers = append(consumers, ref)
		}
	}
	return consumers, nil
}

// ResolveConsumer is Resolve among the credentials access may present. A
// selector naming the device kind is refused with ErrDeviceCredential.
func (s *Store) ResolveConsumer(sel Selector) (Ref, error) {
	if sel.Kind == KindDevice {
		return Ref{}, ErrDeviceCredential
	}
	consumers, err := s.ListConsumers()
	if err != nil {
		return Ref{}, err
	}
	return resolveIn(sel, consumers)
}

func resolveIn(sel Selector, all []Ref) (Ref, error) {
	var found []Ref
	for _, ref := range all {
		if sel.Matches(ref) {
			found = append(found, ref)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		if len(all) == 0 {
			return Ref{}, errcode.New(errcode.NoCredential).With(nil, "")
		}
		return Ref{}, errcode.New(errcode.NoMatchingCredential).With(nil, "this machine holds:\n"+indentRefs(all))
	default:
		// List each candidate in full selector form.
		return Ref{}, errcode.New(errcode.CredentialsAmbiguous).With(nil, "candidates:\n"+indentRefs(found))
	}
}

// Load reads one credential. The key is read through the security package,
// which checks the open descriptor.
func (s *Store) Load(ref Ref) (*Material, error) {
	dir := s.dir(ref)
	if err := s.trusted(dir); err != nil {
		return nil, errUnreadable.With(err, ref.String())
	}

	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		return nil, errUnreadable.With(err, ref.String())
	}
	m, err := loadMaterial(dir, meta)
	if err != nil {
		return nil, errUnreadable.With(err, ref.String())
	}
	return m, nil
}

// loadMaterial reads the key and certificate files meta names.
func loadMaterial(dir string, meta Meta) (*Material, error) {
	key, err := loadKey(dir, meta.Key)
	if err != nil {
		return nil, err
	}
	certPEM, err := security.ReadPrivateFile(filepath.Join(dir, meta.Cert))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return &Material{CertPEM: certPEM, Key: key, Meta: meta}, nil
}

// trusted runs the read-only form of the walk Save does before writing.
// fs.ErrNotExist passes so the read that follows reports it.
func (s *Store) trusted(dir string) error {
	base, follow := s.StateRoot()
	err := security.CheckPrivateDir(base, dir, follow)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Save writes a credential and returns its Ref. The path and the identity
// fields of Meta both come from the certificate.
//
// The certificate and key are written first under serial-named files. Writing
// meta.json commits them, so a crash cannot pair a new key with the old
// certificate.
//
// Save replaces the whole credential: a pending device renewal is discarded,
// since a new enrolment revokes every earlier certificate of the device.
// It stores the certificate only; m.DeviceKeys is the caller's to pass to
// TicketKeys.Replace. It waits up to saveLockWait for a renewal in flight to
// finish, then returns ErrRenewalInProgress; it returns ctx.Err() when ctx
// ends first.
func (s *Store) Save(ctx context.Context, m Material) (Ref, error) {
	ref, err := completeMeta(&m)
	if err != nil {
		return Ref{}, err
	}
	release, err := s.waitLock(ctx, ref, saveLockWait)
	if err != nil {
		return Ref{}, err
	}
	defer release()
	// Created under the lock: a Forget or Remove holding it deletes the
	// whole directory before this Save can use it.
	dir, err := s.ensureCredentialDir(ref)
	if err != nil {
		return ref, err
	}
	if err := s.commitCurrent(dir, &m); err != nil {
		return ref, err
	}
	// A new enrolment supersedes a forgotten device of the same ref; the
	// tombstone sits beside the directory, so replacing it leaves the file.
	if ref.Kind == KindDevice {
		return ref, s.DeleteTombstone(ref)
	}
	return ref, nil
}

// SaveIssued is Save for material a spent one-time secret (join token, setup
// token, login approval) produced. The secret is spent, so cancelling ctx (a
// signal) does not abandon the save; saveLockWait still bounds the wait.
func (s *Store) SaveIssued(ctx context.Context, m Material) (Ref, error) {
	return s.Save(context.WithoutCancel(ctx), m)
}

// saveLocked is Save for a caller that already holds the renewal lock. m.Meta
// is completed in place, so the caller's Material names the files as stored.
func (s *Store) saveLocked(m *Material) (Ref, error) {
	ref, dir, err := s.prepare(m)
	if err != nil {
		return Ref{}, err
	}
	return ref, s.commitCurrent(dir, m)
}

// commitCurrent writes m's files and commits them as the current credential.
// pending.json is removed before meta.json is written: a crash between them
// leaves the previous credential current with nothing pending, never a
// pending certificate beside a credential it was not renewed from.
func (s *Store) commitCurrent(dir string, m *Material) error {
	if err := writeKeyMaterial(dir, m); err != nil {
		return err
	}
	if err := removeIfExists(filepath.Join(dir, pendingFile)); err != nil {
		return err
	}
	if err := writeMeta(dir, metaFile, m.Meta); err != nil {
		return err
	}
	s.sweep(dir, m.Meta.Cert, m.Meta.Key.File)
	return nil
}

// prepare completes m.Meta from the certificate and creates the credential
// directory. It writes no credential file. The caller holds the renewal lock.
func (s *Store) prepare(m *Material) (Ref, string, error) {
	ref, err := completeMeta(m)
	if err != nil {
		return Ref{}, "", err
	}
	dir, err := s.ensureCredentialDir(ref)
	return ref, dir, err
}

// completeMeta completes m.Meta from the certificate and returns its Ref.
func completeMeta(m *Material) (Ref, error) {
	leaf, err := leafOf(m.CertPEM)
	if err != nil {
		return Ref{}, err
	}
	ref, err := RefFromCert(leaf)
	if err != nil {
		return Ref{}, err
	}
	if !ref.valid() {
		return Ref{}, fmt.Errorf("certificate yields an unusable credential ref (%+v)", ref)
	}
	// Identity fields come from the certificate and override the caller's
	// values.
	m.Meta.Team, m.Meta.Kind, m.Meta.Identity = ref.Team, ref.Kind, ref.Identity
	m.Meta.SpiffeID = SpiffeURI(leaf)
	m.Meta.Serial = leaf.SerialNumber.Text(16)
	m.Meta.NotAfter = leaf.NotAfter.UTC()
	m.Meta.Key = m.Key.Ref()
	m.Meta.UpdatedAt = time.Now().UTC()

	// The serial is a path component. Text(16) is hex and always valid.
	if !validPathComponent(m.Meta.Serial) {
		return Ref{}, fmt.Errorf("certificate serial %q is not usable as a filename", m.Meta.Serial)
	}
	m.Meta.Cert = "cert-" + m.Meta.Serial + ".pem"
	m.Meta.Key.File = "key-" + m.Meta.Serial + ".pem"

	// Validate before writing, since readMeta refuses an invalid record.
	if err := m.Meta.validate(); err != nil {
		return Ref{}, fmt.Errorf("refusing to store an unusable credential record: %w", err)
	}
	return ref, nil
}

// ensureCredentialDir creates ref's credential directory and returns it.
func (s *Store) ensureCredentialDir(ref Ref) (string, error) {
	dir := s.dir(ref)
	base, follow := s.StateRoot()
	if err := security.EnsurePrivateDir(base, dir, follow); err != nil {
		return "", err
	}
	return dir, nil
}

// writeKeyMaterial writes m's certificate and key under the names prepare
// chose. They are unused until a metadata file references them.
func writeKeyMaterial(dir string, m *Material) error {
	pk, ok := m.Key.(persistentKey)
	if !ok {
		return errors.New("credential key cannot be written to disk")
	}
	keyPEM, err := pk.marshal()
	if err != nil {
		return err
	}
	if err := security.WritePrivateFileAtomic(filepath.Join(dir, m.Meta.Cert), m.CertPEM); err != nil {
		return err
	}
	return security.WritePrivateFileAtomic(filepath.Join(dir, m.Meta.Key.File), keyPEM)
}

// writeMeta commits meta as the named metadata file.
func writeMeta(dir, name string, meta Meta) error {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity metadata: %w", err)
	}
	return security.WritePrivateFileAtomic(filepath.Join(dir, name), append(raw, '\n'))
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

// sweep removes serial-named files no metadata file references. Errors are
// ignored because leftover files are unused.
func (s *Store) sweep(dir string, keep ...string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if slices.Contains(keep, name) {
			continue
		}
		if strings.HasPrefix(name, "cert-") || strings.HasPrefix(name, "key-") {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}

// validPathComponent reports whether s is safe as a filename inside a
// credential directory.
func validPathComponent(s string) bool {
	if s == "" || s == "." || s == ".." {
		return false
	}
	return !strings.ContainsAny(s, `/\:`)
}

// Dir is where a Ref's files live, for messages that tell an operator what was
// written and where.
func (s *Store) Dir(ref Ref) string { return s.dir(ref) }

// TLSCertificate returns the chain to present with the key as a crypto.Signer.
func (m *Material) TLSCertificate() (*tls.Certificate, error) {
	leaf, err := leafOf(m.CertPEM)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{PrivateKey: m.Key, Leaf: leaf}
	for rest := m.CertPEM; len(rest) > 0; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("credential holds no certificate")
	}
	// Check the key matches the leaf. A mismatch otherwise fails as an opaque
	// bad_certificate alert.
	signer, ok := m.Key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, errors.New("credential key cannot report its public half")
	}
	matches, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("certificate carries an unsupported public key type %T", leaf.PublicKey)
	}
	if !matches.Equal(signer.Public()) {
		remedy := "obtain it again with `localport setup <TOKEN>` or `localport login`"
		if m.Meta.Kind == KindDevice {
			remedy = errcode.NewJoinCommand
		}
		return nil, fmt.Errorf("the stored key does not match the stored certificate (serial %s): the credential is unusable; %s", m.Meta.Serial, remedy)
	}
	return cert, nil
}

// readMeta opens meta.json with the same checks as the key file. It selects
// the key and certificate files and the renewal source.
func readMeta(path string) (Meta, error) {
	raw, err := security.ReadPrivateFile(path)
	if err != nil {
		return Meta{}, fmt.Errorf("read identity metadata: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return Meta{}, fmt.Errorf("parse identity metadata: %w", err)
	}
	if err := meta.validate(); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", path, err)
	}
	return meta, nil
}

// validate refuses incomplete or unknown metadata. encoding/json leaves
// missing fields at zero, so a truncated meta.json still parses.
func (m Meta) validate() error {
	switch {
	case m.Identity == "":
		return errors.New("identity metadata names no identity")
	case m.Team == "":
		return errors.New("identity metadata names no team")
	case !m.Kind.Valid():
		return fmt.Errorf("identity metadata has unknown kind %q", m.Kind)
	case !m.Source.Valid():
		return fmt.Errorf("identity metadata has unknown source %q", m.Source)
	case m.NotAfter.IsZero():
		return errors.New("identity metadata has no expiry")
	case m.RenewAfter != nil && !m.Source.Renewable():
		return fmt.Errorf("identity metadata for a %s credential carries a renewal deadline", m.Source)
	case !validPathComponent(m.Cert):
		return fmt.Errorf("identity metadata names an unusable certificate file %q", m.Cert)
	case !validPathComponent(m.Key.File):
		return fmt.Errorf("identity metadata names an unusable key file %q", m.Key.File)
	case m.Device != nil && m.Kind != KindDevice:
		return fmt.Errorf("identity metadata for a %s credential carries device details", m.Kind)
	}
	return nil
}

func refFromMeta(m Meta) (Ref, error) {
	ref := Ref{Team: m.Team, Kind: m.Kind, Identity: m.Identity}
	if !ref.valid() {
		return Ref{}, fmt.Errorf("incomplete identity metadata for team %q", m.Team)
	}
	return ref, nil
}

func indentRefs(refs []Ref) string {
	lines := make([]string, len(refs))
	for i, r := range refs {
		lines[i] = "    " + r.String()
	}
	return strings.Join(lines, "\n")
}
