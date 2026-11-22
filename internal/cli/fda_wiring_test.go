package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/user"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/config"
	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/session"
	"github.com/localport/agent/internal/tunnel"
)

// readingLauncher refuses every start with startReading, as a launcher that
// read Full Disk Access for the request.
type readingLauncher struct{ startReading string }

func (readingLauncher) Probe(context.Context) (launcher.Probe, error) {
	return launcher.Probe{PAM: true}, nil
}

func (l readingLauncher) Start(context.Context, launcher.Request, *os.File) (*launcher.Session, error) {
	return nil, &launcher.RefusalError{Code: launcher.CodeInternal, FullDiskAccess: l.startReading}
}

// A device with logins reports the runner's shared Full Disk Access state:
// the probe's reading sets it (macOS), and a session start's reading updates
// it through the session server. A device without logins reports none.
func TestDeviceFullDiskAccessFollowsTheLauncher(t *testing.T) {
	saved := probe
	probe = func(context.Context) (launcher.Probe, error) {
		return launcher.Probe{PAM: true, FullDiskAccess: launcher.FullDiskAccessDenied}, nil
	}
	sessionLauncher = readingLauncher{startReading: launcher.FullDiskAccessGranted}
	t.Cleanup(func() { probe, sessionLauncher = saved, nil })

	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	store := &identity.Store{Root: t.TempDir()}
	storeDeviceCredential(t, store, sessionsRef, "eu")
	ticketKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	keys, err := store.TicketKeys(sessionsRef)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(ticketKey.Public().(ed25519.PublicKey))
	if err := keys.Replace(context.Background(), keys.Generation(), identity.DeviceKeys{TicketKeys: []identity.TicketKey{{KID: "k1", PublicKey: pub}}}); err != nil {
		t.Fatal(err)
	}

	r := &deviceRunner{parent: context.Background(), store: store, logEvent: func(s string) { t.Log(s) }, fda: tunnel.NewFullDiskAccessState(), served: map[identity.Ref]*servedDevice{}}
	d := config.LocalDevice{Identity: sessionsRef, Enable: []config.Capability{config.CapabilityTerminal}, Logins: []string{me.Username}}
	spec, ok := r.build(d)
	if !ok {
		t.Fatal("build skipped the device")
	}
	t.Cleanup(func() { r.served[sessionsRef].end() })
	if spec.FullDiskAccess != r.fda {
		t.Fatal("a device with logins does not report the runner's Full Disk Access state")
	}
	if runtime.GOOS == "darwin" {
		if got := r.fda.Load(); got != launcher.FullDiskAccessDenied {
			t.Fatalf("after the probe the state holds %q, want the probe's %q", got, launcher.FullDiskAccessDenied)
		}
	}

	// Sessions are served once the edge acknowledged the registration.
	p, err := spec.Credential.Present()
	if err != nil {
		t.Fatal(err)
	}
	spec.Credential.Registered(p)
	leaf, err := x509.ParseCertificate(p.Certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	startShell(t, spec.SessionHandler, terminalSigner(t, ticketKey, leaf.RawSubjectPublicKeyInfo, me.Username), me.Username, hostKey)
	if got := r.fda.Load(); got != launcher.FullDiskAccessGranted {
		t.Fatalf("after a session start the state holds %q, want the launcher's %q", got, launcher.FullDiskAccessGranted)
	}

	plainRef := identity.Ref{Team: sessionsRef.Team, Kind: identity.KindDevice, Identity: "tun12345.gw-02"}
	storeDeviceCredential(t, store, plainRef, "eu")
	plain, ok := r.build(config.LocalDevice{Identity: plainRef})
	if !ok {
		t.Fatal("build skipped the device without logins")
	}
	if plain.FullDiskAccess != nil {
		t.Fatal("a device without logins reports a Full Disk Access state")
	}
}

// terminalSigner is an SSH certificate signer for a terminal session of login
// on the device whose key has spki, signed by ticketKey.
func terminalSigner(t *testing.T, ticketKey ed25519.PrivateKey, spki []byte, login string) ssh.Signer {
	t.Helper()
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	client, err := ssh.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := json.Marshal(map[string]string{"tunnel": "tun12345", "prefix": "gw-01", "spki_sha256": session.SPKIHash(spki)})
	cert := &ssh.Certificate{
		Key: client.PublicKey(), Serial: 78, CertType: ssh.UserCert, ValidPrincipals: []string{login},
		ValidAfter: uint64(time.Now().Add(-time.Minute).Unix()), ValidBefore: uint64(time.Now().Add(time.Minute).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"device@localport.io": string(dev), "idle@localport.io": "1800"},
			Extensions:      map[string]string{"kind@localport.io": "terminal", "subject@localport.io": `{"subject":"user:alice"}`},
		},
	}
	ca, err := ssh.NewSignerFromKey(ticketKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewCertSigner(cert, client)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startShell serves one stream and asks for a shell on it, which the session
// server passes to its launcher; the launcher's answer is all the test needs.
func startShell(t *testing.T, h interface {
	Serve(net.Conn, [16]byte, uint64, string) bool
}, signer ssh.Signer, login string, hostKey ssh.PublicKey) {
	t.Helper()
	agentSide, clientSide := net.Pipe()
	served := make(chan struct{})
	go func() {
		defer close(served)
		defer agentSide.Close()
		h.Serve(agentSide, [16]byte{2}, 78, "")
	}()
	defer func() {
		_ = clientSide.Close()
		<-served
	}()
	_ = clientSide.SetDeadline(time.Now().Add(10 * time.Second))
	cr, err := session.Hello(clientSide, signer, hostKey)
	if err != nil {
		t.Fatal(err)
	}
	attached := make(chan struct{})
	go func() {
		defer close(attached)
		cr.Conn.Attach(clientSide, 0)
	}()
	defer func() { <-attached }()
	c, chans, reqs, err := ssh.NewClientConn(cr.Conn, "gw-01", &ssh.ClientConfig{
		User: login, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: 10 * time.Second,
	})
	if err != nil {
		cr.Conn.End(err)
		t.Fatal(err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Shell(); err == nil {
		t.Fatal("the shell started; the launcher refuses every start")
	}
}
