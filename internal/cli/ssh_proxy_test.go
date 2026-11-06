package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/session"
)

// proxyEdge is a device behind a test edge: a real session server, a
// WebSocket endpoint that admits each stream by its first message, and a
// mint of session-format certificates for the device.
type proxyEdge struct {
	t       *testing.T
	srv     *session.Server
	hostKey ssh.PublicKey
	ca      ssh.Signer
	spki    string
	http    *httptest.Server

	mu      sync.Mutex
	mints   []identity.SessionRequest
	streams []*websocket.Conn
	serial  uint64
}

func newProxyEdge(t *testing.T) *proxyEdge {
	t.Helper()
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &devKey.PublicKey, devKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	tlsCert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: devKey, Leaf: leaf}
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	e := &proxyEdge{t: t, ca: ca, spki: session.SPKIHash(leaf.RawSubjectPublicKeyInfo), serial: 0x40}
	e.hostKey, _ = ssh.NewPublicKey(&devKey.PublicKey)
	e.srv = session.NewServer(session.ServerConfig{
		Prefix:       "gw-01",
		Certificate:  func() (*tls.Certificate, bool) { return tlsCert, true },
		CAKeys:       func() []ed25519.PublicKey { return []ed25519.PublicKey{caPub} },
		Capabilities: []string{"terminal"},
		Logins:       []string{"pi"},
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = e.srv.Shutdown(ctx)
	})
	e.http = httptest.NewTLSServer(http.HandlerFunc(e.serveStream))
	t.Cleanup(e.http.Close)
	return e
}

func (e *proxyEdge) url() string {
	return "wss" + strings.TrimPrefix(e.http.URL, "https") + "/v1/session"
}

func (e *proxyEdge) serveStream(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	_, first, err := ws.Read(r.Context())
	if err != nil {
		return
	}
	pub, err := ssh.ParsePublicKey(first)
	cert, ok := pub.(*ssh.Certificate)
	if err != nil || !ok {
		_ = ws.Close(4000, "ticket_refused")
		return
	}
	e.mu.Lock()
	e.streams = append(e.streams, ws)
	e.mu.Unlock()
	stream := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	defer stream.Close()
	e.srv.Serve(stream, [16]byte{0x01}, cert.Serial)
}

// mint signs a session certificate as the API would: a resume request gets
// the resume option naming the original certificate's serial.
func (e *proxyEdge) mint(_ context.Context, req identity.SessionRequest) (*identity.SessionCertificate, error) {
	e.mu.Lock()
	e.mints = append(e.mints, req)
	e.serial++
	serial := e.serial
	e.mu.Unlock()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.ClientSSHPubKey))
	if err != nil {
		e.t.Fatalf("client key: %v", err)
	}
	dev, _ := json.Marshal(map[string]string{"tunnel": "abc123", "prefix": "gw-01", "spki_sha256": e.spki})
	cert := &ssh.Certificate{
		Key: pub, Serial: serial, CertType: ssh.UserCert, ValidPrincipals: []string{req.Login},
		ValidAfter: uint64(time.Now().Add(-30 * time.Second).Unix()), ValidBefore: uint64(time.Now().Add(5 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"device@localport.io": string(dev)},
			Extensions:      map[string]string{"kind@localport.io": "ssh", "subject@localport.io": `{"subject":"user:ana"}`},
		},
	}
	if req.ResumeCertificate != "" {
		original, err := parseUserCertificate([]byte(req.ResumeCertificate))
		if err != nil {
			e.t.Fatalf("resume certificate: %v", err)
		}
		cert.CriticalOptions["resume@localport.io"] = strconv.FormatUint(original.Serial, 16)
	}
	if err := cert.SignCert(rand.Reader, e.ca); err != nil {
		e.t.Fatal(err)
	}
	return &identity.SessionCertificate{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		URL:         e.url(),
		HostKey:     string(ssh.MarshalAuthorizedKey(e.hostKey)),
		DeviceHost:  req.DeviceHost,
	}, nil
}

func (e *proxyEdge) state() (mints []identity.SessionRequest, streams []*websocket.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]identity.SessionRequest(nil), e.mints...), append([]*websocket.Conn(nil), e.streams...)
}

// startProxy mints with ssh-cert, runs ssh-proxy on one end of a loopback
// pair and connects an x/crypto SSH client, as OpenSSH would, on the other.
func startProxy(t *testing.T, e *proxyEdge) (*ssh.Client, <-chan error) {
	t.Helper()
	return startProxyWith(t, e, e.mint)
}

// startProxyWith is startProxy with mint answering ssh-proxy's resume mints.
func startProxyWith(t *testing.T, e *proxyEdge, mint sessionMinter) (*ssh.Client, <-chan error) {
	t.Helper()
	target := newSSHTarget(t)
	if err := target.ensureCert(context.Background(), "pi", e.mint, time.Now()); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	clientSide, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxySide := <-accepted
	done := make(chan error, 1)
	go func() {
		defer proxySide.Close()
		done <- target.proxy(context.Background(), proxySide, proxySide, &websocket.DialOptions{HTTPClient: e.http.Client()}, mint)
	}()
	f := target.files()
	key, _ := loadOrCreateClientKey(f.key)
	raw, _ := os.ReadFile(f.cert)
	cert, _ := parseUserCertificate(raw)
	signer, _ := ssh.NewCertSigner(cert, key)
	c, chans, reqs, err := ssh.NewClientConn(clientSide, "gw-01", &ssh.ClientConfig{
		User: "pi", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh through ssh-proxy: %v", err)
	}
	return ssh.NewClient(c, chans, reqs), done
}

func alive(client *ssh.Client) bool {
	done := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		done <- err
	}()
	select {
	case err := <-done:
		return err == nil
	case <-time.After(10 * time.Second):
		return false
	}
}

func proxyResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("ssh-proxy did not return")
		return nil
	}
}

// A stream lost without a close frame is resumed with a resume certificate
// for the original one; the SSH connection carries on, and the end of
// ssh-proxy's input ends the connection on the device at once.
func TestSSHProxyResumesAfterALostStream(t *testing.T) {
	e := newProxyEdge(t)
	client, done := startProxy(t, e)
	if !alive(client) {
		t.Fatal("the connection through ssh-proxy does not answer")
	}
	_, streams := e.state()
	_ = streams[0].CloseNow()
	if !alive(client) {
		t.Fatal("the connection does not answer after the stream was lost")
	}
	mints, streams := e.state()
	if len(mints) != 2 || mints[1].ResumeCertificate == "" || len(streams) != 2 {
		t.Fatalf("mints %d (second resumes: %v), streams %d; want 2, true, 2", len(mints), len(mints) > 1 && mints[1].ResumeCertificate != "", len(streams))
	}
	original, _ := parseUserCertificate([]byte(mints[1].ResumeCertificate))
	if original.Serial != 0x41 {
		t.Fatalf("the resume request names serial %x, want the first certificate's 41", original.Serial)
	}
	_ = client.Close()
	if err := proxyResult(t, done); err != nil {
		t.Fatalf("ssh-proxy after the client closed = %v, want nil", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.LiveSessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the deliberate close left the device connection detached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An edge close for a reason outside sshResumableEnds ends ssh-proxy with
// the reason and no resume.
func TestSSHProxyEndsOnATerminalCloseReason(t *testing.T) {
	e := newProxyEdge(t)
	client, done := startProxy(t, e)
	defer client.Close()
	if !alive(client) {
		t.Fatal("the connection through ssh-proxy does not answer")
	}
	_, streams := e.state()
	_ = streams[0].Close(4000, "kicked")
	err := proxyResult(t, done)
	if err == nil || !strings.Contains(err.Error(), "kicked") {
		t.Fatalf("ssh-proxy = %v, want an error naming kicked", err)
	}
	if mints, _ := e.state(); len(mints) != 1 {
		t.Fatalf("%d mints, want 1: a terminal close must not resume", len(mints))
	}
}

// sshResumableEnds is the list agent/docs/PROTOCOL.md names (the browser
// pins its RESUMABLE_ENDS to docs/COMMUNICATION.md the same way).
func TestSSHResumableEndsMatchTheProtocolDoc(t *testing.T) {
	doc, err := os.ReadFile("../../docs/PROTOCOL.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(doc), "a reason in `sshResumableEnds` (")
	if !ok {
		t.Fatal("PROTOCOL.md names no sshResumableEnds list")
	}
	list, _, _ := strings.Cut(rest, ")")
	var named []string
	for _, f := range strings.Split(list, ",") {
		named = append(named, strings.Trim(strings.TrimSpace(f), "`"))
	}
	slices.Sort(named)
	want := slices.Clone(sshResumableEnds)
	slices.Sort(want)
	if !slices.Equal(named, want) {
		t.Fatalf("PROTOCOL.md lists %v, the code %v", named, want)
	}
}

// A resume mint with no answer, a rate limit or a 5xx is retried within the
// window; any other answer, or a local failure, ends the session.
func TestResumeMintRetryable(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"no answer", &url.Error{Op: "Post", URL: "https://api", Err: errors.New("connection refused")}, true},
		{"rate limited", &identity.APIError{Status: http.StatusTooManyRequests}, true},
		{"SE032", &identity.APIError{Status: http.StatusServiceUnavailable}, true},
		{"SE036", &identity.APIError{Status: http.StatusForbidden}, false},
		{"local", errors.New("credential expired"), false},
	} {
		if got := resumeMintRetryable(fmt.Errorf("wrapped: %w", c.err)); got != c.want {
			t.Errorf("%s: retryable = %v, want %v", c.name, got, c.want)
		}
	}
}

// ssh-proxy keeps resuming while the mint gets no answer and resumes once it
// answers again.
func TestSSHProxyRetriesAResumeMintWithNoAnswer(t *testing.T) {
	e := newProxyEdge(t)
	var failing atomic.Int32
	failing.Store(2)
	mint := e.mint
	flaky := func(ctx context.Context, req identity.SessionRequest) (*identity.SessionCertificate, error) {
		if req.ResumeCertificate != "" && failing.Add(-1) >= 0 {
			return nil, &url.Error{Op: "Post", URL: "https://api", Err: errors.New("network is unreachable")}
		}
		return mint(ctx, req)
	}
	client, done := startProxyWith(t, e, flaky)
	defer client.Close()
	_, streams := e.state()
	_ = streams[0].CloseNow()
	if !alive(client) {
		t.Fatal("the connection did not resume after the mint answered again")
	}
	select {
	case err := <-done:
		t.Fatalf("ssh-proxy ended: %v", err)
	default:
	}
}
