package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/localport/agent/internal/identity"
)

const testDeviceHost = "gw-01-factory.eu.localport.dev"

func newSSHTarget(t *testing.T) sshTarget {
	t.Helper()
	base := t.TempDir()
	return sshTarget{
		store: &identity.Store{Root: filepath.Join(base, "identity"), Base: base, BaseChosen: true},
		ref:   identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindUser, Identity: "ana"},
		host:  testDeviceHost,
	}
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// fakeMint signs a certificate for the requested key and login with a test
// CA, valid for life from now, and counts its calls.
type fakeMint struct {
	t       *testing.T
	ca      ssh.Signer
	hostKey ssh.PublicKey
	now     time.Time
	life    time.Duration
	calls   int
	edit    func(*identity.SessionCertificate)
}

func newFakeMint(t *testing.T, now time.Time) *fakeMint {
	return &fakeMint{t: t, ca: testSigner(t), hostKey: testHostKey(t), now: now, life: 5 * time.Minute}
}

func (m *fakeMint) mint(_ context.Context, req identity.SessionRequest) (*identity.SessionCertificate, error) {
	m.calls++
	if req.Kind != sshSessionKind || req.DeviceHost != testDeviceHost {
		m.t.Errorf("request = %+v", req)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.ClientSSHPubKey))
	if err != nil {
		m.t.Fatalf("client key: %v", err)
	}
	cert := &ssh.Certificate{
		Key: pub, Serial: uint64(m.calls), CertType: ssh.UserCert, ValidPrincipals: []string{req.Login},
		ValidAfter: uint64(m.now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(m.now.Add(m.life).Unix()),
	}
	if err := cert.SignCert(rand.Reader, m.ca); err != nil {
		m.t.Fatal(err)
	}
	resp := &identity.SessionCertificate{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		URL:         "wss://edge-1.ns.localport.dev/v1/session",
		HostKey:     string(ssh.MarshalAuthorizedKey(m.hostKey)),
		DeviceHost:  req.DeviceHost,
	}
	if m.edit != nil {
		m.edit(resp)
	}
	return resp, nil
}

func TestParseDeviceHost(t *testing.T) {
	if got, err := parseDeviceHost(" GW-01-Factory.eu.localport.dev. "); err != nil || got != testDeviceHost {
		t.Fatalf("parseDeviceHost = %q, %v", got, err)
	}
	for _, bad := range []string{"", "gw-01", "../etc", "a/b.dev", "a b.dev", "-a.dev", "a..dev", strings.Repeat("a", 64) + ".dev"} {
		if _, err := parseDeviceHost(bad); err == nil {
			t.Errorf("parseDeviceHost(%q) accepted", bad)
		}
	}
}

// ssh-cert mints once, reuses the certificate while sshCertMinRemaining or
// more is left, and mints again below it or for another login; the client
// key stays the same throughout.
func TestSSHCertMintsOnceAndReusesWhileFresh(t *testing.T) {
	target := newSSHTarget(t)
	now := time.Now()
	m := newFakeMint(t, now)
	ctx := context.Background()
	if err := target.ensureCert(ctx, "pi", m.mint, now); err != nil {
		t.Fatal(err)
	}
	f := target.files()
	key, err := os.ReadFile(f.key)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{f.key, f.cert, f.url, f.knownHosts} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
				t.Errorf("%s: mode %v, %v; want 0600", p, fi.Mode().Perm(), err)
			}
		}
	}
	if err := target.ensureCert(ctx, "pi", m.mint, now.Add(time.Minute)); err != nil || m.calls != 1 {
		t.Fatalf("reuse: calls = %d, %v; want 1", m.calls, err)
	}
	if err := target.ensureCert(ctx, "pi", m.mint, now.Add(m.life-sshCertMinRemaining+time.Second)); err != nil || m.calls != 2 {
		t.Fatalf("near expiry: calls = %d, %v; want 2", m.calls, err)
	}
	if err := target.ensureCert(ctx, "root", m.mint, now); err != nil || m.calls != 3 {
		t.Fatalf("other login: calls = %d, %v; want 3", m.calls, err)
	}
	if again, _ := os.ReadFile(f.key); string(again) != string(key) {
		t.Fatal("the client key changed")
	}
	raw, _ := os.ReadFile(f.cert)
	cert, err := parseUserCertificate(raw)
	if err != nil || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("certificate = %v, %v; want the root one", cert, err)
	}
}

// After a mint, known_hosts makes ssh accept exactly the host key of the
// response for the device alias: a stale entry for the alias is replaced and
// other hosts' entries are kept.
func TestKnownHostsHoldsExactlyTheMintedHostKey(t *testing.T) {
	target := newSSHTarget(t)
	now := time.Now()
	m := newFakeMint(t, now)
	stale, other := testHostKey(t), testHostKey(t)
	f := target.files()
	if err := os.MkdirAll(filepath.Dir(f.knownHosts), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := "other.eu.localport.dev " + string(ssh.MarshalAuthorizedKey(other)) + testDeviceHost + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(stale)))
	if err := os.WriteFile(f.knownHosts, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := target.ensureCert(context.Background(), "pi", m.mint, now); err != nil {
		t.Fatal(err)
	}
	check, err := knownhosts.New(f.knownHosts)
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}
	if err := check(testDeviceHost+":22", addr, m.hostKey); err != nil {
		t.Fatalf("the minted host key is refused: %v", err)
	}
	for name, key := range map[string]ssh.PublicKey{"stale": stale, "another": testHostKey(t)} {
		if err := check(testDeviceHost+":22", addr, key); err == nil {
			t.Errorf("%s host key accepted for the device", name)
		}
	}
	if err := check("other.eu.localport.dev:22", addr, other); err != nil {
		t.Errorf("another host's entry was dropped: %v", err)
	}
}

// A response that does not match the request writes nothing.
func TestSSHCertRefusesAMismatchedResponse(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	now := time.Now()
	for name, edit := range map[string]func(*testing.T, *fakeMint) func(*identity.SessionCertificate){
		"another key": func(t *testing.T, m *fakeMint) func(*identity.SessionCertificate) {
			return func(r *identity.SessionCertificate) {
				cert := &ssh.Certificate{Key: testSigner(t).PublicKey(), CertType: ssh.UserCert, ValidPrincipals: []string{"pi"}, ValidBefore: uint64(now.Add(time.Hour).Unix())}
				_ = cert.SignCert(rand.Reader, m.ca)
				r.Certificate = string(ssh.MarshalAuthorizedKey(cert))
			}
		},
		"plain key": func(t *testing.T, m *fakeMint) func(*identity.SessionCertificate) {
			return func(r *identity.SessionCertificate) {
				r.Certificate = string(ssh.MarshalAuthorizedKey(testSigner(t).PublicKey()))
			}
		},
		"rsa host key": func(*testing.T, *fakeMint) func(*identity.SessionCertificate) {
			return func(r *identity.SessionCertificate) { r.HostKey = string(ssh.MarshalAuthorizedKey(rsaPub)) }
		},
		"plain http": func(*testing.T, *fakeMint) func(*identity.SessionCertificate) {
			return func(r *identity.SessionCertificate) { r.URL = "http://edge/v1/session" }
		},
		"expired": func(_ *testing.T, m *fakeMint) func(*identity.SessionCertificate) {
			m.life = -time.Second
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			target := newSSHTarget(t)
			m := newFakeMint(t, now)
			m.edit = edit(t, m)
			if err := target.ensureCert(context.Background(), "pi", m.mint, now); err == nil {
				t.Fatal("accepted")
			}
			f := target.files()
			for _, p := range []string{f.cert, f.url, f.knownHosts} {
				if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s written: %v", filepath.Base(p), err)
				}
			}
		})
	}
}

func TestSSHConfigBlock(t *testing.T) {
	target := newSSHTarget(t)
	f := target.files()
	block, err := target.sshConfigBlock("/opt/local port/100%/localport")
	if err != nil {
		t.Fatal(err)
	}
	ref := target.ref.String()
	for _, want := range []string{
		"Host " + testDeviceHost + "\n",
		`  ProxyCommand "/opt/local port/100%%/localport" ssh-proxy --identity ` + ref + " %r %h\n",
		"  IdentityFile " + sshConfigValue(f.key) + "\n",
		"  CertificateFile " + sshConfigValue(f.cert) + "\n",
		"  UserKnownHostsFile " + sshConfigValue(f.knownHosts) + "\n",
		"  HostKeyAlias " + testDeviceHost + "\n",
		"  StrictHostKeyChecking yes\n",
		"  IdentitiesOnly yes\n",
		`Match host ` + testDeviceHost + ` exec "\"/opt/local port/100%%/localport\" ssh-cert --identity ` + ref + ` %r %h"` + "\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	if _, err := target.sshConfigBlock("/opt/\"q\"/localport"); err == nil {
		t.Error("a path with a quote accepted")
	}
}

func TestOpensshBeforePQ(t *testing.T) {
	for out, want := range map[string]bool{
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13": true,
		"OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2":      true,
		"OpenSSH_8.9p1":                true,
		"OpenSSH_9.9p1, OpenSSL 3.4.0": false,
		"OpenSSH_10.0p2":               false,
		"something else":               false,
	} {
		if _, got := opensshBeforePQ(out); got != want {
			t.Errorf("opensshBeforePQ(%q) = %v, want %v", out, got, want)
		}
	}
}
