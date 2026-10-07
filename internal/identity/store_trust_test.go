//go:build !windows

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/localport/agent/internal/security"
)

const trustTestSubject = "spiffe://01kpq7x2abcd34.mtls.localport.dev/client/deploy-prod"

// savedCredential saves one credential and returns the store, its ref,
// directory and meta.
func savedCredential(t *testing.T) (*Store, Ref, string, Meta) {
	t.Helper()
	store := &Store{Root: t.TempDir()}
	ref, err := store.Save(credentialFor(t, trustTestSubject))
	if err != nil {
		t.Fatal(err)
	}
	dir := store.Dir(ref)
	meta, err := readMeta(filepath.Join(dir, metaFile))
	if err != nil {
		t.Fatal(err)
	}
	return store, ref, dir, meta
}

// replaceWithLink renames path and puts a symlink to the renamed file in its
// place.
func replaceWithLink(t *testing.T, path string) {
	t.Helper()
	moved := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

// Load accepts everything Save writes.
func TestLoadAcceptsWhatSaveWrites(t *testing.T) {
	store, ref, _, _ := savedCredential(t)
	if _, err := store.Load(ref); err != nil {
		t.Fatalf("a freshly saved credential does not load: %v", err)
	}
}

// meta.json behind a symlink is refused.
func TestLoadRefusesSymlinkedMeta(t *testing.T) {
	store, ref, dir, _ := savedCredential(t)
	replaceWithLink(t, filepath.Join(dir, metaFile))
	if _, err := store.Load(ref); err == nil {
		t.Fatal("a record reached through a link was loaded")
	}
}

func TestLoadRefusesSymlinkedCert(t *testing.T) {
	store, ref, dir, meta := savedCredential(t)
	replaceWithLink(t, filepath.Join(dir, meta.Cert))
	if _, err := store.Load(ref); err == nil {
		t.Fatal("a certificate reached through a link was loaded")
	}
}

// A group-writable meta.json is refused.
func TestLoadRefusesAGroupWritableMeta(t *testing.T) {
	store, ref, dir, _ := savedCredential(t)
	if err := os.Chmod(filepath.Join(dir, metaFile), 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); err == nil {
		t.Fatal("a group-writable record was loaded")
	}
}

// A symlinked renewal lock is refused before O_CREATE or O_RDWR reach its
// target.
func TestRenewLockRefusesSymlink(t *testing.T) {
	store, ref, dir, _ := savedCredential(t)
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.Remove(filepath.Join(dir, lockFile))
	if err := os.Symlink(victim, filepath.Join(dir, lockFile)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	r := &Renewer{Store: store, Ref: ref}
	if release, held, err := r.lock(); err == nil {
		if held {
			release()
		}
		t.Fatal("the renewal lock was opened through a link")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("the link's target was created")
	}
}

// Load and List refuse a symlinked credential or team directory, as Save does.
func TestLoadAndListRefuseALinkedDirectory(t *testing.T) {
	for name, pick := range map[string]func(dir string) string{
		"credential directory": func(dir string) string { return dir },
		"team directory":       filepath.Dir,
	} {
		t.Run(name, func(t *testing.T) {
			store, ref, dir, _ := savedCredential(t)
			replaceWithLink(t, pick(dir))

			if _, err := store.Load(ref); !errors.Is(err, security.ErrUntrustedPath) {
				t.Fatalf("Load through a linked %s: err = %v, want ErrUntrustedPath", name, err)
			}
			refs, skipped, err := store.ListWithSkipped()
			if err != nil {
				t.Fatal(err)
			}
			if len(refs) != 0 || len(skipped) != 1 || !errors.Is(skipped[0].Reason, security.ErrUntrustedPath) {
				t.Fatalf("List through a linked %s: refs = %v, skipped = %+v; want the credential skipped as untrusted", name, refs, skipped)
			}
		})
	}
}

// A missing credential is fs.ErrNotExist, not ErrUntrustedPath.
func TestLoadOfAMissingCredentialIsNotATrustError(t *testing.T) {
	store := &Store{Root: t.TempDir()}
	ref, err := refFromMeta(savedMeta(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); err == nil || errors.Is(err, security.ErrUntrustedPath) {
		t.Fatalf("Load of a missing credential: err = %v, want a not-found error", err)
	}
}

func savedMeta(t *testing.T) Meta {
	t.Helper()
	_, _, _, meta := savedCredential(t)
	return meta
}
