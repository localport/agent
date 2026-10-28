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
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
	"github.com/localport/agent/internal/session"
)

// A renewed certificate acknowledged while its promotion is refused (the
// renewal lock is held, so Store.Load does not return it) serves sessions:
// the wired server checks tickets against its SPKI and signs the accept
// frame with its key. A terminal ticket for the current user bound to it is
// accepted; a ticket bound to another key is refused as for another device.
func TestDeviceSessionsUseTheRegisteredCertificate(t *testing.T) {
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

	lock, err := security.OpenLockFile(filepath.Join(store.Dir(sessionsRef), ".renew.lock"))
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
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil)
	if err != nil || spec.SessionHandler == nil {
		t.Fatalf("deviceSessions = %v, %v; want a session server", state, err)
	}
	defer state.jti.Close()

	client, err := session.GenerateClientKeys()
	if err != nil {
		t.Fatal(err)
	}
	ticket := func(spki []byte, jti string) []byte {
		now := time.Now().Unix()
		body, err := json.Marshal(session.Ticket{
			V: 1, KID: "k1", JTI: jti, IAT: now, EXP: now + 60,
			Team: "team-1", Tunnel: "tun12345", Device: "gw-01", DeviceSPKISHA256: session.SPKIHash(spki),
			Edge: "edge-1", Subject: "user:alice", Kind: "terminal", Login: me.Username,
			ClientX25519: enc.EncodeToString(client.X25519.PublicKey().Bytes()),
			ClientMLKEM:  enc.EncodeToString(client.MLKEM.EncapsulationKey().Bytes()),
		})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(enc.EncodeToString(body) + "." + enc.EncodeToString(ed25519.Sign(ticketKey, body)))
	}
	spki := renewed.Leaf.RawSubjectPublicKeyInfo
	raw := ticket(spki, "0190a000-0000-7000-8000-0000000000aa")
	frame := firstFrame(t, spec.SessionHandler, raw)
	var msg session.AcceptMessage
	if err := json.Unmarshal(frame, &msg); err != nil || msg.Type != "accept" {
		t.Fatalf("renewed: first frame %s, %v; want accept", frame, err)
	}
	// Open verifies the accept signature against the renewed certificate.
	if _, err := session.Open(raw, spki, &msg, client); err != nil {
		t.Fatalf("renewed: the accept frame is not signed with the renewed key: %v", err)
	}
	other := selfSignedDevice(t)
	if got := firstFrameCode(t, spec.SessionHandler, ticket(other.Leaf.RawSubjectPublicKeyInfo, "0190a000-0000-7000-8000-0000000000ab")); got != session.CodeTicketWrongDevice {
		t.Errorf("another key: refused %q, want %q", got, session.CodeTicketWrongDevice)
	}
}

// firstFrameCode serves one stream carrying raw and returns the refusal code
// of the agent's first frame.
func firstFrameCode(t *testing.T, h interface{ Serve(net.Conn) }, raw []byte) string {
	t.Helper()
	frame := firstFrame(t, h, raw)
	var m struct{ Type, Code string }
	if err := json.Unmarshal(frame, &m); err != nil || m.Type != "refused" {
		t.Fatalf("first frame %s, %v; want a refusal", frame, err)
	}
	return m.Code
}

// firstFrame serves one stream carrying raw, returns the agent's first frame
// and closes the stream.
func firstFrame(t *testing.T, h interface{ Serve(net.Conn) }, raw []byte) []byte {
	t.Helper()
	agentSide, clientSide := net.Pipe()
	defer clientSide.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		h.Serve(agentSide)
		agentSide.Close()
	}()
	_ = clientSide.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := clientSide.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(raw))), raw...)); err != nil {
		t.Fatal(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(clientSide, head[:]); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, binary.BigEndian.Uint32(head[:]))
	if _, err := io.ReadFull(clientSide, frame); err != nil {
		t.Fatal(err)
	}
	clientSide.Close()
	<-served
	return frame
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

// A second process on the same identity cannot take .jti.lock and sets no
// session handler; the revoked-kid hook is still set.
func TestDeviceSessionsNeedTheJTILog(t *testing.T) {
	store := sessionsStore(t)
	held, err := session.OpenJTILog(store.Dir(sessionsRef), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	spec := config.DeviceSpec{
		Name: "gw-01", Credential: identity.NewDeviceRegistrar(store, sessionsRef, nil), Capabilities: []string{"terminal"},
	}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil)
	if !errors.Is(err, session.ErrJTILogLocked) || state != nil {
		t.Fatalf("deviceSessions = %v, %v; want ErrJTILogLocked", state, err)
	}
	if spec.SessionHandler != nil {
		t.Fatal("a session handler was set without the jti log")
	}
	if spec.HintRevoked == nil {
		t.Fatal("HintRevoked is not set")
	}
}

// A device that enables no session capability gets no session server.
func TestDeviceSessionsNeedACapability(t *testing.T) {
	store := sessionsStore(t)
	spec := config.DeviceSpec{Name: "gw-01", Credential: identity.NewDeviceRegistrar(store, sessionsRef, nil)}
	state, err := deviceSessions(store, sessionsRef, &spec, nil, nil)
	if err != nil || state != nil || spec.SessionHandler != nil {
		t.Fatalf("deviceSessions = %v, %v, handler %v; want none", state, err, spec.SessionHandler)
	}
}
