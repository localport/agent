package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/localport/agent/internal/errcode"
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
	f := target.files("pi")
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
	raw, _ := os.ReadFile(target.files("root").cert)
	cert, err := parseUserCertificate(raw)
	if err != nil || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("certificate = %v, %v; want the root one", cert, err)
	}
	// Each login keeps its own certificate: pi's still serves, so neither run
	// re-mints the other's (concurrent `ssh root@` and `ssh alice@`).
	if err := target.ensureCert(ctx, "pi", m.mint, now.Add(time.Minute)); err != nil || m.calls != 3 {
		t.Fatalf("pi after root: calls = %d, %v; want 3", m.calls, err)
	}
	raw, _ = os.ReadFile(f.cert)
	if cert, err := parseUserCertificate(raw); err != nil || cert.ValidPrincipals[0] != "pi" {
		t.Fatalf("pi's certificate = %v, %v; want pi's", cert, err)
	}
}

// refusedOnEveryClient are logins no client OS accepts: they cannot name a
// file or would act in ssh_config's shell commands.
var refusedOnEveryClient = []string{"", "..", "a/b", "-oProxyCommand=x", "a;b", "$(id)", "a`id`", "a'b", `a"b`, "a|b", "a&b", "a>b", "a(b)", "{a}"}

// ssh-cert and ssh-proxy refuse such a login before any mint or file read.
func TestSSHHelpersRefuseALoginBeforeAnyWork(t *testing.T) {
	target := newSSHTarget(t)
	m := newFakeMint(t, time.Now())
	for _, login := range refusedOnEveryClient {
		refused := errcode.New(errcode.SSHLoginRefused)
		if err := target.ensureCert(context.Background(), login, m.mint, time.Now()); !errors.Is(err, refused) {
			t.Errorf("ssh-cert login %q = %v, want a login refusal", login, err)
		}
		if err := target.proxy(context.Background(), login, strings.NewReader(""), io.Discard, nil, m.mint); !errors.Is(err, refused) {
			t.Errorf("ssh-proxy login %q = %v, want a login refusal", login, err)
		}
	}
	if m.calls != 0 {
		t.Fatalf("calls = %d, want no mint", m.calls)
	}
}

// ssh-proxy only reads the client files: without a certificate or a key it
// fails with AG101 naming ssh-cert, and it creates no key.
func TestSSHProxyWithoutClientFilesCreatesNothing(t *testing.T) {
	target := newSSHTarget(t)
	m := newFakeMint(t, time.Now())
	f := target.files("pi")
	proxy := func() error {
		return target.proxy(context.Background(), "pi", strings.NewReader(""), io.Discard, nil, m.mint)
	}
	if err := proxy(); !errors.Is(err, errNoSessionCert) || !strings.Contains(err.Error(), "localport ssh-cert") {
		t.Fatalf("no files: proxy = %v, want AG101 naming ssh-cert", err)
	}
	if err := target.ensureCert(context.Background(), "pi", m.mint, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.key); err != nil {
		t.Fatal(err)
	}
	if err := proxy(); !errors.Is(err, errNoSessionCert) {
		t.Fatalf("no key: proxy = %v, want AG101", err)
	}
	if _, err := os.Stat(f.key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("proxy created the key: %v", err)
	}
}

// ssh-cert waits for the lock another holds and gives up when its context
// ends, minting nothing; once the lock is free it mints.
func TestSSHCertWaitsForTheLock(t *testing.T) {
	target := newSSHTarget(t)
	m := newFakeMint(t, time.Now())
	f := target.files("pi")
	if err := os.MkdirAll(filepath.Dir(f.lock), 0o700); err != nil {
		t.Fatal(err)
	}
	release, err := identity.WaitLockFile(context.Background(), f.lock, time.Second, errSSHFilesBusy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := target.ensureCert(ctx, "pi", m.mint, time.Now()); !errors.Is(err, context.DeadlineExceeded) || m.calls != 0 {
		t.Fatalf("held: ensureCert = %v, calls %d; want the deadline and no mint", err, m.calls)
	}
	release()
	if err := target.ensureCert(context.Background(), "pi", m.mint, time.Now()); err != nil || m.calls != 1 {
		t.Fatalf("free: ensureCert = %v, calls %d; want one mint", err, m.calls)
	}
}

// A backslash, * and ? name no Windows file; elsewhere a backslash passes
// unless it would escape the next one or the closing quote. A UPN login
// and a login with a space pass everywhere.
func TestCheckSSHLoginPerClientOS(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, login := range refusedOnEveryClient {
			if checkSSHLogin(login, goos) == nil {
				t.Errorf("%s: login %q accepted", goos, login)
			}
		}
		for _, login := range []string{"pi", "alice@corp.example", "John Smith", "a-b.c_d"} {
			if err := checkSSHLogin(login, goos); err != nil {
				t.Errorf("%s: login %q = %v", goos, login, err)
			}
		}
	}
	for login, windowsOK := range map[string]bool{`CORP\alice`: false, "a*b": false, "a?b": false} {
		if err := checkSSHLogin(login, "linux"); err != nil {
			t.Errorf("linux: login %q = %v", login, err)
		}
		if got := checkSSHLogin(login, "windows") == nil; got != windowsOK {
			t.Errorf("windows: login %q accepted = %v", login, got)
		}
	}
	for _, login := range []string{`alice\`, `a\\b`} {
		if checkSSHLogin(login, "linux") == nil {
			t.Errorf("linux: login %q accepted", login)
		}
	}
}

// splitLoginHost splits at the last @, as ssh does.
func TestSplitLoginHost(t *testing.T) {
	for arg, want := range map[string][2]string{
		"pi@" + testDeviceHost:                 {"pi", testDeviceHost},
		"alice@corp.example@" + testDeviceHost: {"alice@corp.example", testDeviceHost},
	} {
		login, host, err := splitLoginHost(arg)
		if err != nil || login != want[0] || host != want[1] {
			t.Errorf("splitLoginHost(%q) = %q, %q, %v; want %q", arg, login, host, err, want)
		}
	}
	if _, _, err := splitLoginHost("@" + testDeviceHost); err == nil {
		t.Error("an empty login accepted")
	}
}

// ssh_config paths: a quote, $, ` or a line break is refused everywhere, a
// backslash outside Windows.
func TestCheckSSHConfigPath(t *testing.T) {
	for _, goos := range []string{"linux", "windows"} {
		for _, p := range []string{`/opt/"q"/localport`, "/home/$USER/x", "/opt/`id`", "/opt/a\nb", "/opt/a\rb"} {
			if checkSSHConfigPath(p, goos) == nil {
				t.Errorf("%s: path %q accepted", goos, p)
			}
		}
		for _, p := range []string{"/opt/local port/100%/localport", "/opt/a;b|c&(d)/localport"} {
			if err := checkSSHConfigPath(p, goos); err != nil {
				t.Errorf("%s: path %q = %v", goos, p, err)
			}
		}
	}
	if err := checkSSHConfigPath(`C:\Program Files (x86)\Localport\localport.exe`, "windows"); err != nil {
		t.Errorf("windows: program path = %v", err)
	}
	if checkSSHConfigPath(`/opt/a\b/localport`, "linux") == nil {
		t.Error("linux: a backslash accepted")
	}
}

// Each credential keeps its own known_hosts: a mint with one credential
// leaves the host key another credential trusts for the same device.
func TestKnownHostsPerCredential(t *testing.T) {
	ana := newSSHTarget(t)
	bob := ana
	bob.ref.Identity = "bob"
	now := time.Now()
	ma, mb := newFakeMint(t, now), newFakeMint(t, now)
	if ana.files("pi").knownHosts == bob.files("pi").knownHosts {
		t.Fatal("two credentials share known_hosts")
	}
	if err := ana.ensureCert(context.Background(), "pi", ma.mint, now); err != nil {
		t.Fatal(err)
	}
	if err := bob.ensureCert(context.Background(), "pi", mb.mint, now); err != nil {
		t.Fatal(err)
	}
	if key, err := knownHostKey(ana.files("pi").knownHosts, testDeviceHost); err != nil || !bytes.Equal(key.Marshal(), ma.hostKey.Marshal()) {
		t.Fatalf("ana's host key = %v, %v; want her mint's", key, err)
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
	f := target.files("pi")
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
			f := target.files("pi")
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
	f := target.files("%r")
	block, err := target.sshConfigBlock("/opt/local port/100%/localport")
	if err != nil {
		t.Fatal(err)
	}
	ref := target.ref.String()
	// ssh expands %r to the login, naming files("<login>").
	keep := func(path string) string { return strings.ReplaceAll(sshConfigValue(path), "%%r@", "%r@") }
	for _, want := range []string{
		"Host " + testDeviceHost + "\n",
		`  ProxyCommand "/opt/local port/100%%/localport" ssh-proxy --identity ` + ref + ` "%r" "%h"` + "\n",
		"  IdentityFile " + keep(f.key) + "\n",
		"  CertificateFile " + keep(f.cert) + "\n",
		"  UserKnownHostsFile " + sshConfigValue(f.knownHosts) + "\n",
		"  HostKeyAlias " + testDeviceHost + "\n",
		"  StrictHostKeyChecking yes\n",
		"  IdentitiesOnly yes\n",
		`Match host ` + testDeviceHost + ` exec "\"/opt/local port/100%%/localport\" ssh-cert --identity ` + ref + ` \"%r\" \"%h\""` + "\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	// An exe without a space is quoted too, so a shell character in it stays
	// part of the path.
	block, err = target.sshConfigBlock("/opt/a;b/localport")
	if err != nil || !strings.Contains(block, `  ProxyCommand "/opt/a;b/localport" ssh-proxy`) {
		t.Errorf("block = %q, %v; want the exe quoted", block, err)
	}
	if _, err := target.sshConfigBlock("/opt/\"q\"/localport"); err == nil {
		t.Error("a path with a quote accepted")
	}
}

// The post-quantum notice of `localport ssh` (below 9.9) and the name filter
// warning of ssh-config (below 9.6).
func TestOpensshBefore(t *testing.T) {
	for out, want := range map[string][2]bool{
		"OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13": {true, false},
		"OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2":      {true, true},
		"OpenSSH_8.9p1":                {true, true},
		"OpenSSH_9.9p1, OpenSSL 3.4.0": {false, false},
		"OpenSSH_10.0p2":               {false, false},
		"something else":               {false, false},
	} {
		_, pq := opensshBefore(out, sshPQMinMajor, sshPQMinMinor)
		_, filter := opensshBefore(out, sshNameFilterMajor, sshNameFilterMinor)
		if pq != want[0] || filter != want[1] {
			t.Errorf("opensshBefore(%q) = pq %v, filter %v; want %v", out, pq, filter, want)
		}
	}
	if w := opensshNameFilterWarning("9.5"); !strings.Contains(w, "OpenSSH 9.5") || !strings.Contains(w, "9.6 or later") {
		t.Errorf("warning = %q", w)
	}
}
