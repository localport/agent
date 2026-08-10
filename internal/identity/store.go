// Package identity holds the machine's own mTLS credential: how it is obtained,
// where it lives on disk, and how it renews itself.
//
// A machine spends a setup token once and keeps a private key that never leaves
// it. From then on the CERTIFICATE is the credential for getting the next one,
// so no long-lived secret stays on the box.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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
	certFile = "cert.pem"
	keyFile  = "key.pem"
	metaFile = "meta.json"
	lockFile = ".renew.lock"
)

// Source is how a credential was obtained. Written to meta.json, so the values
// are a stored format: do not repurpose one.
type Source string

const (
	SourceToken Source = "token" // setup token, renews itself
)

// Meta is the record beside the key material.
//
// APIURL is stored rather than re-derived, so a renewal is never told which
// control plane issued the credential.
type Meta struct {
	Identity   string    `json:"identity"`
	Team       string    `json:"team"`
	Kind       Kind      `json:"kind"`
	SpiffeID   string    `json:"spiffe_id"`
	Key        KeyRef    `json:"key"`
	Source     Source    `json:"source"`
	APIURL     string    `json:"api_url"`
	Serial     string    `json:"serial"`
	NotAfter   time.Time `json:"not_after"`
	RenewAfter time.Time `json:"renew_after"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Material is one stored credential: the certificate chain we present, the key
// that proves it is ours, and the metadata that drives renewal.
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

// Dir is where a Ref's files live, for messages that tell an operator what was
// written and where.
func (s *Store) Dir(ref Ref) string { return s.dir(ref) }

// List returns every stored credential, sorted. The Ref is read from meta.json
// rather than decoded back out of the path, so the directory names stay purely
// a legibility aid.
func (s *Store) List() ([]Ref, error) {
	matches, err := filepath.Glob(filepath.Join(s.Root, "*", "*", metaFile))
	if err != nil {
		return nil, fmt.Errorf("read identity store: %w", err)
	}
	refs := make([]Ref, 0, len(matches))
	for _, path := range matches {
		meta, err := readMeta(path)
		if err != nil {
			return nil, err
		}
		ref, err := refFromMeta(meta)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].dir() < refs[j].dir() })
	return refs, nil
}

// Resolve picks the one credential a selector names. Ambiguity is an error
// rather than a guess: the wrong identity surfaces as a refused handshake, far
// from the choice that caused it.
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
			return Ref{}, fmt.Errorf("no credential on this machine")
		}
		return Ref{}, fmt.Errorf("no credential matches; this machine holds:\n%s", indentRefs(all))
	default:
		// The full form of each candidate, so the fix is a paste.
		return Ref{}, fmt.Errorf("several credentials match; narrow with --identity:\n%s", indentRefs(found))
	}
}

// Load reads one credential. The key goes through the security package, which
// validates the open descriptor rather than the path.
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
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	return &Material{CertPEM: certPEM, Key: key, Meta: meta}, nil
}

// Save writes a credential and returns where it landed. The destination and
// Meta's identity fields both come from the certificate, so meta.json and the
// path cannot disagree.
//
// Each file is written atomically, so a concurrent reader never sees a partial
// key. The key goes first: a certificate without its key is useless, a key
// without its certificate merely unused.
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
	// Taken from the certificate, never from what the caller passed: a record
	// describing a different credential than the one beside it drives every later
	// decision, from which principal is presented to when it expires.
	m.Meta.Team, m.Meta.Kind, m.Meta.Identity = ref.Team, ref.Kind, ref.Identity
	m.Meta.SpiffeID = SpiffeURI(leaf)
	m.Meta.Serial = leaf.SerialNumber.Text(16)
	m.Meta.NotAfter = leaf.NotAfter.UTC()
	m.Meta.Key = m.Key.Ref()
	m.Meta.UpdatedAt = time.Now().UTC()

	dir := s.dir(ref)

	if err := security.EnsurePrivateDir(s.Root, dir); err != nil {
		return Ref{}, err
	}

	metaRaw, err := json.MarshalIndent(m.Meta, "", "  ")
	if err != nil {
		return Ref{}, fmt.Errorf("encode identity metadata: %w", err)
	}

	type storedFile struct {
		name string
		data []byte
	}
	var files []storedFile
	// Only when there is material to write.
	if pk, ok := m.Key.(persistentKey); ok {
		keyPEM, err := pk.marshal()
		if err != nil {
			return Ref{}, err
		}
		files = append(files, storedFile{keyFile, keyPEM})
	}
	files = append(files,
		storedFile{certFile, m.CertPEM},
		storedFile{metaFile, append(metaRaw, '\n')},
	)

	for _, f := range files {
		if err := security.WritePrivateFileAtomic(filepath.Join(dir, f.name), f.data); err != nil {
			return Ref{}, err
		}
	}
	return ref, nil
}

// TLSCertificate builds the chain to present. The key is attached as a
// crypto.Signer.
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
		return nil, fmt.Errorf("credential holds no certificate")
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
	return meta, nil
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

func leafOf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate in PEM data")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf, nil
}
