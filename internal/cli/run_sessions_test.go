package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/session"
)

// A renewed certificate acknowledged while its promotion is refused (the
// renewal lock is held, so Store.Load does not return it) serves sessions:
// the wired server checks session certificates against its SPKI and signs
// the accept frame with its key. A terminal certificate for the current user
// bound to it is accepted; one bound to another key is refused as for
// another device.
func TestDeviceSessionsUseTheRegisteredCertificate(t *testing.T) {
	sessionLauncher = probingLauncher{}
	t.Cleanup(func() { sessionLauncher = nil })
	store := sessionsStore(t)
	enc := base64.RawURLEncoding
	ticketKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys, err := store.TicketKeys(sessionsRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Replace(context.Background(), keys.Generation(), identity.DeviceKeys{TicketKeys: []identity.TicketKey{{KID: "k1", PublicKey: enc.EncodeToString(ticketKey.Public().(ed25519.PublicKey))}}}); err != nil {
		t.Fatal(err)
	}

	lock, err := security.OpenLockFile(filepath.Join(sessionsLockDir(t, store), ".renew.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if held, err := security.TryLockFile(lock); err != nil || !held {
		t.Fatalf("renewal lock: held=%v err=%v", held, err)
	}
	renewed := selfSignedDevice(t)
	reg := identity.NewDeviceRegistrar(store, sessionsRef, nil)
	reg.Registered(&identity.Presentation{Certificate: renewed, Serial: "renewed", Pending: true})
	if _, err := store.Load(sessionsRef); err == nil {
		t.Fatal("Store.Load returns a certificate; the test needs it to lag the acknowledgement")
	}

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	spec := config.DeviceSpec{Name: "gw-01", Credential: reg, Capabilities: []string{"terminal"}, Logins: []string{me.Username}}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil, nil)
	if err != nil || spec.SessionHandler == nil {
		t.Fatalf("deviceSessions = %v, %v; want a session server", state, err)
	}
	defer state.unshare()
	defer state.lock.Close()

	const serial = 77
	mint := func(spki []byte) ssh.Signer {
		_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
		client, err := ssh.NewSignerFromKey(clientKey)
		if err != nil {
			t.Fatal(err)
		}
		dev, _ := json.Marshal(map[string]string{"tunnel": "tun12345", "prefix": "gw-01", "spki_sha256": session.SPKIHash(spki)})
		cert := &ssh.Certificate{
			Key: client.PublicKey(), Serial: serial, CertType: ssh.UserCert, ValidPrincipals: []string{me.Username},
			ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix()),
			Permissions: ssh.Permissions{
				CriticalOptions: map[string]string{"device@localport.io": string(dev), "idle@localport.io": "1800"},
				Extensions:      map[string]string{"kind@localport.io": "terminal", "subject@localport.io": `{"subject":"user:alice"}`},
			},
		}
		ca, _ := ssh.NewSignerFromKey(ticketKey)
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewCertSigner(cert, client)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}
	renewedHost, err := ssh.NewPublicKey(renewed.Leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// The renewed key is the host key, and a certificate bound to it passes.
	if err := sshHandshake(t, spec.SessionHandler, serial, mint(renewed.Leaf.RawSubjectPublicKeyInfo), me.Username, renewedHost); err != nil {
		t.Fatalf("renewed: %v", err)
	}
	other := selfSignedDevice(t)
	if err := sshHandshake(t, spec.SessionHandler, serial, mint(other.Leaf.RawSubjectPublicKeyInfo), me.Username, renewedHost); err == nil {
		t.Error("a certificate bound to another device key passed userauth")
	}
}

// sshHandshake serves one stream and runs an SSH client's handshake and
// userauth on it.
func sshHandshake(t *testing.T, h interface {
	Serve(net.Conn, [16]byte, uint64, string) bool
}, serial uint64, signer ssh.Signer, user string, hostKey ssh.PublicKey) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		agentSide, err := ln.Accept()
		if err != nil {
			return
		}
		defer agentSide.Close()
		h.Serve(agentSide, [16]byte{1}, serial, "")
	}()
	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = clientSide.Close()
		<-served
	}()
	_ = clientSide.SetDeadline(time.Now().Add(10 * time.Second))
	cr, err := session.Hello(clientSide, signer, hostKey)
	if err != nil {
		return err
	}
	attached := make(chan struct{})
	go func() {
		defer close(attached)
		cr.Conn.Attach(clientSide, 0)
	}()
	c, _, _, err := ssh.NewClientConn(cr.Conn, "gw-01", &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 10 * time.Second,
	})
	if err == nil {
		_ = c.Close()
	} else {
		cr.Conn.End(err)
	}
	<-attached
	return err
}

func selfSignedDevice(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "gw-01"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

var sessionsRef = identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: "tun12345.gw-01"}

// sessionsStore is a store holding sessionsRef's identity directory only.
func sessionsStore(t *testing.T) *identity.Store {
	t.Helper()
	store := &identity.Store{Root: t.TempDir()}
	if err := os.MkdirAll(store.Dir(sessionsRef), 0o700); err != nil {
		t.Fatal(err)
	}
	return store
}

func sessionsLockDir(t *testing.T, store *identity.Store) string {
	t.Helper()
	dir, err := store.LockDir(sessionsRef)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// A second process on the same identity cannot take .sessions.lock and sets
// no session handler; the revoked-kid hook is still set.
func TestDeviceSessionsNeedTheSessionsLock(t *testing.T) {
	store := sessionsStore(t)
	held, err := session.LockSessions(sessionsLockDir(t, store))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	spec := config.DeviceSpec{
		Name: "gw-01", Credential: identity.NewDeviceRegistrar(store, sessionsRef, nil), Capabilities: []string{"terminal"},
	}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil, nil)
	if !errors.Is(err, session.ErrSessionsLocked) || state != nil {
		t.Fatalf("deviceSessions = %v, %v; want ErrSessionsLocked", state, err)
	}
	if spec.SessionHandler != nil {
		t.Fatal("a session handler was set without the sessions lock")
	}
	if spec.HintRevoked == nil {
		t.Fatal("HintRevoked is not set")
	}
}

// The sessions lock is held under a shared hold of the store lock for the
// device's lifetime: a purge waits while the device serves sessions and runs
// once the device ends.
func TestDeviceSessionsHoldTheStoreUntilTheDeviceEnds(t *testing.T) {
	store := sessionsStore(t)
	spec := config.DeviceSpec{
		Name: "gw-01", Credential: identity.NewDeviceRegistrar(store, sessionsRef, nil), Capabilities: []string{"terminal"},
	}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil, nil)
	if err != nil || state == nil {
		t.Fatalf("deviceSessions = %v, %v; want a session state", state, err)
	}
	served := &servedDevice{lock: state.lock, unshare: state.unshare}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := store.PurgeDevices(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("purge while the device serves sessions = %v, want it to wait", err)
	}
	served.end()
	if _, err := store.PurgeDevices(context.Background(), nil); err != nil {
		t.Fatalf("purge after the device ended = %v", err)
	}
}

// A device that enables no session capability gets no session server.
func TestDeviceSessionsNeedACapability(t *testing.T) {
	store := sessionsStore(t)
	spec := config.DeviceSpec{Name: "gw-01", Credential: identity.NewDeviceRegistrar(store, sessionsRef, nil)}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil, nil)
	if err != nil || state != nil || spec.SessionHandler != nil {
		t.Fatalf("deviceSessions = %v, %v, handler %v; want none", state, err, spec.SessionHandler)
	}
}

// probingLauncher answers the probe that precedes a terminal session and
// starts nothing.
type probingLauncher struct{}

func (probingLauncher) Probe(context.Context) (launcher.Probe, error) {
	return launcher.Probe{PAM: true, FullDiskAccess: launcher.FullDiskAccessUnknown}, nil
}

func (probingLauncher) Start(context.Context, launcher.Request, *os.File) (*launcher.Session, error) {
	return nil, launcher.Refusal(launcher.CodeInternal)
}
