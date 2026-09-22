// Package identity obtains, stores and renews the machine's mTLS credential.
//
// A machine redeems a setup token once. The private key stays on the machine,
// and the current certificate authorizes each renewal.
package identity

import (
	"crypto"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/localport/agent/internal/security"
)

const (
	metaFile = "meta.json"
	lockFile = ".renew.lock"
)

// Source is how a credential was obtained. Values are persisted in meta.json
// and must not change meaning.
type Source string

const (
	SourceToken Source = "token" // setup token, renews itself
	SourceOIDC  Source = "oidc"  // CI workload identity, held in memory
	SourceSSO   Source = "sso"   // `localport login`, short-lived, for a person
)

// Renewable reports whether a credential from this source can be reissued.
// Unknown sources are not renewable. A sign-in does not renew, the user signs
// in again.
func (s Source) Renewable() bool {
	switch s {
	case SourceToken, SourceOIDC:
		return true
	default:
		return false
	}
}

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
}

// Store is a directory of credentials, one subdirectory per Ref.
type Store struct {
	Root string
}

// HomeEnv overrides where credentials live.
const HomeEnv = "LOCALPORT_HOME"

// DefaultStore roots the store at ~/.localport/identity, or at the machine-wide
// state directory when there is no home to use.
func DefaultStore() (*Store, error) {
	root, err := defaultRoot()
	if err != nil {
		return nil, err
	}
	return &Store{Root: filepath.Join(root, "identity")}, nil
}

func defaultRoot() (string, error) {
	if v := strings.TrimSpace(os.Getenv(HomeEnv)); v != "" {
		return v, nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".localport"), nil
	}
	// systemd sets $HOME only when the unit names a User=, so a service without
	// one has no home to use.
	switch runtime.GOOS {
	case "windows":
		programData := strings.TrimSpace(os.Getenv("ProgramData"))
		if programData == "" {
			return "", fmt.Errorf("locate credential directory: neither a home directory nor %%ProgramData%% is set (set %s)", HomeEnv)
		}
		return filepath.Join(programData, "localport"), nil
	case "darwin":
		return "/Library/Application Support/localport", nil
	default:
		return "/var/lib/localport", nil
	}
}

func (s *Store) dir(ref Ref) string { return filepath.Join(s.Root, filepath.FromSlash(ref.dir())) }

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

// Remove deletes a credential's directory. LOCAL ONLY: the certificate stays
// valid until it is revoked. Callers must say so, or an operator reads the
// deletion as a withdrawal of access.
func (s *Store) Remove(ref Ref) error {
	dir := s.dir(ref)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("no credential at %s: %w", dir, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove credential %s: %w", ref, err)
	}
	return nil
}

// Resolve returns the one credential a selector names. An ambiguous selector
// is an error.
func (s *Store) Resolve(sel Selector) (Ref, error) {
	all, err := s.List()
	if err != nil {
		return Ref{}, err
	}
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
			return Ref{}, errors.New("no credential on this machine (run: localport login, or localport setup <TOKEN>)")
		}
		return Ref{}, fmt.Errorf("no credential matches; this machine holds:\n%s", indentRefs(all))
	default:
		// List each candidate in full selector form.
		return Ref{}, fmt.Errorf("several credentials match; narrow with --identity:\n%s", indentRefs(found))
	}
}

// Load reads one credential. The key is read through the security package,
// which checks the open descriptor.
func (s *Store) Load(ref Ref) (*Material, error) {
	dir := s.dir(ref)

	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		return nil, err
	}
	key, err := loadKey(dir, meta.Key)
	if err != nil {
		return nil, fmt.Errorf("no usable credential for %s: %w", ref, err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, meta.Cert))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return &Material{CertPEM: certPEM, Key: key, Meta: meta}, nil
}

// Save writes a credential and returns its Ref. The path and the identity
// fields of Meta both come from the certificate.
//
// The certificate and key are written first under serial-named files. Writing
// meta.json commits them, so a crash cannot pair a new key with the old
// certificate.
func (s *Store) Save(m Material) (Ref, error) {
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

	pk, ok := m.Key.(persistentKey)
	if !ok {
		return Ref{}, errors.New("credential key cannot be written to disk")
	}
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

	dir := s.dir(ref)

	if err := security.EnsurePrivateDir(s.Root, dir); err != nil {
		return Ref{}, err
	}

	metaRaw, err := json.MarshalIndent(m.Meta, "", "  ")
	if err != nil {
		return Ref{}, fmt.Errorf("encode identity metadata: %w", err)
	}

	keyPEM, err := pk.marshal()
	if err != nil {
		return Ref{}, err
	}

	write := func(name string, data []byte) error {
		return security.WritePrivateFileAtomic(filepath.Join(dir, name), data)
	}

	// Unused until meta.json references them.
	if err := write(m.Meta.Cert, m.CertPEM); err != nil {
		return Ref{}, err
	}
	if err := write(m.Meta.Key.File, keyPEM); err != nil {
		return Ref{}, err
	}
	if err := write(metaFile, append(metaRaw, '\n')); err != nil {
		return Ref{}, err
	}

	s.sweep(dir, m.Meta.Cert, m.Meta.Key.File)
	return ref, nil
}

// sweep removes serial-named files left by earlier saves. Errors are ignored
// because leftover files are unused.
func (s *Store) sweep(dir, keepCert, keepKey string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == keepCert || name == keepKey {
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
		return nil, fmt.Errorf("the stored key does not match the stored certificate (serial %s): the credential is unusable and must be obtained again with `localport setup <TOKEN>` or `localport login`", m.Meta.Serial)
	}
	return cert, nil
}

func readMeta(path string) (Meta, error) {
	raw, err := os.ReadFile(path)
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
