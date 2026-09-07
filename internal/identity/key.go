package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"

	"github.com/localport/agent/internal/security"
)

// Backing names where a private key lives. Written to meta.json, so these are a
// stored format: do not repurpose one.
type Backing string

const BackingFile Backing = "file"

// KeyRef records enough to find a key again. A file key needs nothing beyond
// its backing: it always sits at key.pem beside the certificate, and recording
// the path as well would let meta.json disagree with where the file is.
type KeyRef struct {
	Backing Backing `json:"backing"`
}

// Key is a private key the agent holds and signs with. It is a crypto.Signer,
// which is what tls.Certificate and the renewal request both take.
type Key interface {
	crypto.Signer
	Ref() KeyRef
}

// persistentKey is a Key whose material is written beside the certificate, so
// Save can tell what there is to write.
type persistentKey interface {
	Key
	marshal() ([]byte, error)
}

// fileKey is a P-256 key stored as a PKCS#8 PEM file.
type fileKey struct{ *ecdsa.PrivateKey }

func (k fileKey) Ref() KeyRef { return KeyRef{Backing: BackingFile} }

func (k fileKey) marshal() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encode key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// generateKey creates a key of the given backing. P-256 throughout: it is what
// the control plane issues against.
func generateKey(b Backing) (Key, error) {
	switch b {
	case BackingFile, "":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		return fileKey{key}, nil
	default:
		return nil, fmt.Errorf("unsupported key backing %q", b)
	}
}

// loadKey opens the key a credential's metadata points at.
func loadKey(dir string, ref KeyRef) (Key, error) {
	switch ref.Backing {
	case BackingFile, "":
		return loadFileKey(dir)
	default:
		return nil, fmt.Errorf("unsupported key backing %q", ref.Backing)
	}
}

func loadFileKey(dir string) (Key, error) {
	pemBytes, err := security.ReadPrivateFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no private key in PEM data")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return fileKey{key}, nil
	default:
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not ECDSA")
		}
		return fileKey{key}, nil
	}
}
