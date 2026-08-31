package identity

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// reloadCheckInterval bounds how often a handshake stats the credential.
// Modification time rather than a watcher: the writer may be this process or a
// separate `localport identity renew`, so the file is the only thing both see.
const reloadCheckInterval = time.Second

// Credential is a live view of a stored identity. It hands tls.Config a
// callback rather than a fixed certificate, so a long-running
// `localport access` picks up a renewal without restarting.
type Credential struct {
	store *Store
	ref   Ref
	// spiffeID pins the principal seen at Open. A renewal carries the identity
	// forward, so a change means a swapped credential, not a rotation.
	spiffeID string

	mu       sync.Mutex
	cert     *tls.Certificate
	meta     Meta
	modTime  time.Time
	lastStat time.Time
	// onSwap reports a refused reload. Optional.
	onSwap func(string)
}

// Open resolves a selector to one credential and returns a reloading view of it.
func Open(store *Store, sel Selector) (*Credential, error) {
	ref, err := store.Resolve(sel)
	if err != nil {
		return nil, err
	}
	return OpenRef(store, ref)
}

// OpenRef opens exactly the credential a Ref names. Resolving a Ref through a
// selector would list the whole store to rediscover an answer the caller holds,
// and re-run the ambiguity check on a choice already made.
func OpenRef(store *Store, ref Ref) (*Credential, error) {
	c := &Credential{store: store, ref: ref}
	if err := c.reload(); err != nil {
		return nil, err
	}
	c.spiffeID = c.meta.SpiffeID
	return c, nil
}

// OnSwap registers a callback for a refused reload.
func (c *Credential) OnSwap(fn func(string)) { c.onSwap = fn }

// Ref is the credential this view is bound to.
func (c *Credential) Ref() Ref { return c.ref }

// Meta returns the metadata as of the last load.
func (c *Credential) Meta() Meta {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.meta
}

// Certificate returns the current client certificate, reloading it first if the
// file changed since it was last read.
func (c *Credential) Certificate() (*tls.Certificate, error) {
	c.mu.Lock()
	stale := c.staleLocked()
	c.mu.Unlock()

	if stale {
		if err := c.reload(); err != nil {
			// A failed reload keeps serving what we hold: a renewal caught
			// mid-write is transient and must not drop a working credential.
			c.mu.Lock()
			cert := c.cert
			c.mu.Unlock()
			if cert != nil {
				return cert, nil
			}
			return nil, err
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert == nil {
		return nil, fmt.Errorf("no client certificate loaded")
	}
	return c.cert, nil
}

// commitPoint is the file whose mtime means a new credential is fully written.
// Store.Save writes meta.json last, so watching cert.pem would fire between the
// two and pair a new certificate with the previous record.
func (c *Credential) commitPoint() string {
	return filepath.Join(c.store.dir(c.ref), metaFile)
}

func (c *Credential) staleLocked() bool {
	now := time.Now()
	if now.Sub(c.lastStat) < reloadCheckInterval {
		return false
	}
	c.lastStat = now
	info, err := os.Stat(c.commitPoint())
	if err != nil {
		return false
	}
	return !info.ModTime().Equal(c.modTime)
}

func (c *Credential) reload() error {
	// Stamped before the read. Stamping after would record a renewal that landed
	// mid-read as already loaded, and this view would keep serving the superseded
	// certificate. The older stamp costs one redundant reload.
	var modTime time.Time
	if info, statErr := os.Stat(c.commitPoint()); statErr == nil {
		modTime = info.ModTime()
	}

	m, err := c.store.Load(c.ref)
	if err != nil {
		return err
	}
	leaf, err := leafOf(m.CertPEM)
	if err != nil {
		return err
	}
	// Refuse a file that now holds a different principal: presenting it would
	// authenticate this process as somebody else, mid-session.
	if got := SpiffeURI(leaf); c.spiffeID != "" && got != c.spiffeID {
		if c.onSwap != nil {
			c.onSwap(fmt.Sprintf("refused reload: %s now holds %s, not %s", c.store.dir(c.ref), got, c.spiffeID))
		}
		return fmt.Errorf("credential at %s was replaced with a different identity (%s, expected %s)",
			c.store.dir(c.ref), got, c.spiffeID)
	}
	cert, err := m.TLSCertificate()
	if err != nil {
		return fmt.Errorf("load credential %s: %w", c.ref, err)
	}

	c.mu.Lock()
	c.cert, c.meta, c.modTime = cert, m.Meta, modTime
	c.mu.Unlock()
	return nil
}

// GetClientCertificate is the tls.Config hook. The error is not swallowed: a
// handshake with no client certificate draws an opaque refusal from the far
// side instead of a local message naming the file.
func (c *Credential) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return c.Certificate()
}
