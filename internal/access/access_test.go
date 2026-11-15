package access

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/localport/agent/internal/errcode"
)

func TestParseDevice(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantAddr string
		wantErr  bool
	}{
		{in: "plc-01-factory.ap.localport.dev", wantHost: "plc-01-factory.ap.localport.dev", wantAddr: "plc-01-factory.ap.localport.dev:443"},
		{in: "https://plc-01.example.com", wantHost: "plc-01.example.com", wantAddr: "plc-01.example.com:443"},
		{in: "plc-01.example.com:443/path", wantHost: "plc-01.example.com", wantAddr: "plc-01.example.com:443"},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		host, addr, err := ParseDevice(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseDevice(%q) accepted an empty address", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseDevice(%q): %v", tc.in, err)
		}
		if host != tc.wantHost || addr != tc.wantAddr {
			t.Fatalf("ParseDevice(%q) = (%q, %q), want (%q, %q)", tc.in, host, addr, tc.wantHost, tc.wantAddr)
		}
	}
}

// -L uses OpenSSH order, local port then device port.
func TestParseForward(t *testing.T) {
	cases := []struct {
		in        string
		wantLocal string
		wantPort  uint16
		wantErr   bool
	}{
		{in: "5020:502", wantLocal: "127.0.0.1:5020", wantPort: 502},
		{in: "502", wantLocal: "127.0.0.1:0", wantPort: 502},
		{in: "0:22", wantLocal: "127.0.0.1:0", wantPort: 22},
		{in: "5020:0", wantErr: true},
		{in: "5020:70000", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ParseForward(tc.in, "127.0.0.1")
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseForward(%q) accepted a bad value", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseForward(%q): %v", tc.in, err)
		}
		if got.LocalAddr != tc.wantLocal || got.RemotePort != tc.wantPort {
			t.Fatalf("ParseForward(%q) = %+v, want %s -> %d", tc.in, got, tc.wantLocal, tc.wantPort)
		}
	}
}

// Each refusal status maps to an actionable message.
func TestStatusErrorsAreActionable(t *testing.T) {
	cases := map[int]string{
		403: "port 502 is allowed",
		421: "address does not match",
		405: "not a fleet device address",
		502: "nothing is listening on port 502",
		503: "device is busy",
	}
	for status, want := range cases {
		err := statusError(502, status)
		if err == nil {
			t.Fatalf("status %d produced no error", status)
		}
		if !contains(err.Error(), want) {
			t.Fatalf("status %d says %q, want it to mention %q", status, err.Error(), want)
		}
	}
	// An unmapped status stays out of the user text; --verbose names it.
	err := statusError(502, 418)
	if text, hidden := errcode.Render(err); strings.Contains(text, "418") || !hidden || !strings.Contains(err.Error(), "418") {
		t.Fatalf("unmapped status: Render = %q, %v; Error() = %q", text, hidden, err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestLoadAccessConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.yaml")
	body := `
version: 1
access:
  - device: plc-01-factory.ap.localport.dev
    identity: deploy-prod
    forward: ["5020:502", "8080:80"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cc, err := LoadAccessConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cc.Access) != 1 || len(cc.Access[0].Forward) != 2 {
		t.Fatalf("config = %+v", cc)
	}
	if !cc.Access[0].UsesIdentity() {
		t.Fatal("an entry with no file must use the stored identity")
	}
}

// Each refusal shows the user its reason, not only the code.
func TestLoadAccessConfigRefusesIncompleteEntries(t *testing.T) {
	cases := map[string]struct{ body, reason string }{
		"version 2":   {"version: 2\naccess: []\n", "unsupported config version 2"},
		"no devices":  {"version: 1\naccess: []\n", "no devices listed"},
		"no forward":  {"version: 1\naccess:\n  - device: gw.example.com\n", "'forward' needs at least one port"},
		"no device":   {"version: 1\naccess:\n  - forward: [\"502\"]\n", "'device' is required"},
		"file and id": {"version: 1\naccess:\n  - device: gw.example.com\n    forward: [\"502\"]\n    identity: x\n    p12: /tmp/x.p12\n", "cannot be combined"},
		"bad forward": {"version: 1\naccess:\n  - device: gw.example.com\n    forward: [\"99999\"]\n", "-L 99999: device port must be 1-65535"},
		"bad yaml":    {"version: 1\naccess: [\n", "yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "access.yaml")
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadAccessConfig(path)
			if !errors.Is(err, errcode.New(errcode.AccessConfigInvalid)) {
				t.Fatalf("LoadAccessConfig = %v, want AG122", err)
			}
			if text, hidden := errcode.Render(err); !strings.Contains(text, c.reason) || hidden {
				t.Fatalf("Render = %q, %v; want the reason %q shown", text, hidden, c.reason)
			}
		})
	}
}

// Closed connections end every forward and are not reported as errors.
func TestNormalCloseIsNotReported(t *testing.T) {
	for _, err := range []error{nil, io.EOF, net.ErrClosed, syscall.ECONNRESET, syscall.EPIPE} {
		if !isNormalClose(err) {
			t.Fatalf("%v must count as a normal close", err)
		}
	}
	if isNormalClose(errors.New("connection reset by peer, mid-write")) {
		t.Fatal("an unrecognised failure must still be reported")
	}
}

func TestLoadAccessConfigRefusesTwoCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	pemFile := filepath.Join(dir, "client.pem")
	p12 := filepath.Join(dir, "client.p12")
	for _, f := range []string{pemFile, p12} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	path := filepath.Join(dir, "access.yaml")
	body := "version: 1\naccess:\n  - device: gw.example.com\n    forward: [\"502\"]\n    pem: " +
		pemFile + "\n    p12: " + p12 + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadAccessConfig(path)
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("want both credential files refused, got %v", err)
	}
}

// A missing credential file fails at load time.
func TestLoadAccessConfigRefusesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.yaml")
	body := "version: 1\naccess:\n  - device: gw.example.com\n    forward: [\"502\"]\n    p12: " +
		filepath.Join(dir, "absent.p12") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAccessConfig(path); err == nil {
		t.Fatal("want a missing credential file refused")
	}
}

// A local port used by two entries fails at load time.
func TestLoadAccessConfigRefusesDuplicateLocalPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.yaml")
	body := `
version: 1
access:
  - device: gw-01.eu.localport.dev
    forward: ["8080:80"]
  - device: gw-02.eu.localport.dev
    forward: ["8080:8080"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := LoadAccessConfig(path)
	if err == nil || !strings.Contains(err.Error(), "8080") {
		t.Fatalf("err = %v, want both devices named on port 8080", err)
	}
}

// Repeated OS-assigned local ports do not collide.
func TestLoadAccessConfigAllowsRepeatedOSPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.yaml")
	body := `
version: 1
access:
  - device: gw-01.eu.localport.dev
    forward: ["502", "80"]
  - device: gw-02.eu.localport.dev
    forward: ["502"]
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAccessConfig(path); err != nil {
		t.Fatalf("load: %v", err)
	}
}

// Cancelling ends a forward that is mid-copy with an idle peer. The device
// accepts the CONNECT and then sends nothing, so only closing the stream and
// the local connection can end the copy.
func TestProxyRunReturnsWithAForwardOpen(t *testing.T) {
	release := make(chan struct{})
	device := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	device.EnableHTTP2 = true
	device.StartTLS()
	defer device.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		Session: &Session{
			Device:    "gw-01",
			Addr:      device.Listener.Addr().String(),
			TLSConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, //nolint:gosec // test server
		},
		Forwards: []Forward{{LocalAddr: "127.0.0.1:0", RemotePort: 502}},
	}
	bound := make(chan string, 1)
	connected := make(chan struct{}, 1)
	p.OnListen = func(_ Forward, addr string) { bound <- addr }
	p.OnConn = func(string, uint16) { connected <- struct{}{} }

	returned := make(chan error, 1)
	go func() { returned <- p.Run(ctx) }()

	client, err := net.Dial("tcp", <-bound)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer client.Close()

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("the forward never opened a stream to the device")
	}

	cancel()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancellation")
	}
}

// clientConn holds s.mu across dial and handshake, so an unreachable device
// must time out on connectTimeout independent of ctx.
func TestSessionDialIsBoundedIndependentlyOfTheCallerContext(t *testing.T) {
	old := connectTimeout
	connectTimeout = 300 * time.Millisecond
	defer func() { connectTimeout = old }()

	// The listener accepts and never writes, so the TLS handshake hangs as
	// with a blackholed edge.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()

	s := &Session{
		Device:    "gw-01.eu.localport.dev",
		Addr:      ln.Addr().String(),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}

	start := time.Now()
	_, err = s.Open(context.Background(), 502)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the handshake to fail against a silent listener")
	}
	if elapsed > connectTimeout+2*time.Second {
		t.Fatalf("Open took %v, want it bounded near connectTimeout (%v)", elapsed, connectTimeout)
	}
	if elapsed < connectTimeout {
		t.Fatalf("Open returned in %v, before connectTimeout (%v) could have elapsed", elapsed, connectTimeout)
	}
}

// Unknown keys in an access file are errors.
func TestLoadAccessConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.yaml")
	body := "version: 1\naccess:\n  - device: gw-01.eu.localport.dev\n    forwards: [\"5020:502\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAccessConfig(path)
	if err == nil {
		t.Fatal("expected the unknown field to be refused")
	}
	if !strings.Contains(err.Error(), "forwards") {
		t.Fatalf("error should name the field, got %q", err)
	}
}

// A missing credential file is AG121 and the user sees its path and reason.
func TestBuildTLSConfigNamesFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	_, err := BuildTLSConfig(missing, "", "", "gw-01.eu.localport.dev:443", "")
	if !errors.Is(err, errcode.New(errcode.ClientCertUnusable)) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing PEM file: %v, want AG121 with the not-exist cause", err)
	}
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("missing PEM file: %v, want a *fs.PathError in the chain", err)
	}
	if text, _ := errcode.Render(err); !strings.Contains(text, "open "+missing+": "+pathErr.Err.Error()) {
		t.Fatalf("rendered %q, want the path and reason", text)
	}

	// Windows has no mode bits to loosen. There the DACL decides, and a file
	// in the user's temp dir inherits an owner-only one.
	if runtime.GOOS == "windows" {
		return
	}

	// A PEM file readable by group or other is refused before parsing.
	open := filepath.Join(t.TempDir(), "open.pem")
	if err := os.WriteFile(open, []byte("not a PEM file"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = BuildTLSConfig(open, "", "", "gw-01.eu.localport.dev:443", "")
	if err == nil {
		t.Fatal("want an error for a world-readable PEM file")
	}
	if !strings.Contains(err.Error(), "too-open permissions") {
		t.Fatalf("error should name the permissions, got %q", err)
	}
}

// refusalCases are the refusal alerts with the next step each one names.
var refusalCases = []struct {
	code tls.AlertError
	want string
}{
	{42, "refused this certificate"},
	{46, "refused this certificate"},
	{116, "refused this certificate"},
	{48, "refused this certificate"},
	{44, "cannot be renewed"},
	{49, "denied this identity"},
	{45, "run `localport login` again"},
}

// assertRefusal checks that err is a refusal of the device naming want.
func assertRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if !errors.Is(err, errcode.New(errcode.DeviceRefused)) {
		t.Fatalf("error %v, want %s", err, errcode.DeviceRefused)
	}
	for _, s := range []string{want, "gw-01.eu.localport.dev"} {
		if !strings.Contains(err.Error(), s) {
			t.Fatalf("error %q, want it to mention %q", err, s)
		}
	}
}

// replyPeer is a TCP peer that reads the first record it gets, the
// ClientHello, and answers with reply.
func replyPeer(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(hdr[3:]))); err != nil {
					return
				}
				_, _ = c.Write(reply)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// A refusal alert in answer to the ClientHello is a refusal with the next
// step for its code, not an unreachable device.
func TestHandshakeAlertsAreRefusals(t *testing.T) {
	for _, tc := range refusalCases {
		t.Run(strconv.Itoa(int(tc.code)), func(t *testing.T) {
			s := echoSession(t, nil)
			s.Addr = replyPeer(t, []byte{21, 3, 3, 0, 2, 2, byte(tc.code)})
			defer s.Close()
			_, err := s.Open(context.Background(), 22)
			assertRefusal(t, err, tc.want)
		})
	}
	t.Run("other alert", func(t *testing.T) {
		s := echoSession(t, nil)
		s.Addr = replyPeer(t, []byte{21, 3, 3, 0, 2, 2, 40}) // handshake_failure
		defer s.Close()
		_, err := s.Open(context.Background(), 22)
		if !errors.Is(err, errcode.New(errcode.DeviceUnreachable)) || !strings.Contains(err.Error(), "offline") {
			t.Fatalf("error %v, want %s offline", err, errcode.DeviceUnreachable)
		}
	})
}

// A peer that answers the ClientHello with something other than TLS is named
// as such.
func TestHandshakeWithANonTLSPeer(t *testing.T) {
	s := echoSession(t, nil)
	s.Addr = replyPeer(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	defer s.Close()
	_, err := s.Open(context.Background(), 22)
	if !errors.Is(err, errcode.New(errcode.DeviceUnreachable)) || !strings.Contains(err.Error(), "not answering with TLS") {
		t.Fatalf("error %v, want %s not answering with TLS", err, errcode.DeviceUnreachable)
	}
}

// An open stream whose edge sends a refusal alert ends with the refusal, read
// through the HTTP/2 stream; any other end reads as an ended connection.
func TestMidStreamAlertsAreRefusals(t *testing.T) {
	for _, tc := range refusalCases {
		t.Run(strconv.Itoa(int(tc.code)), func(t *testing.T) {
			s := echoSession(t, alertingEdge(t, byte(tc.code)))
			defer s.Close()
			p := &Proxy{Session: s}
			err := p.ServeStdio(context.Background(), strings.NewReader("ping"), io.Discard, 22)
			assertRefusal(t, err, tc.want)
		})
	}
	if msg := streamError("gw-01", io.ErrUnexpectedEOF); !errors.Is(msg, errcode.New(errcode.DeviceUnreachable)) || !strings.Contains(msg.Error(), "ended") {
		t.Fatalf("an unmapped failure reads as %q", msg)
	}
}

// A forward's stream ended by a refusal alert reports the refusal.
func TestMidStreamAlertOnAForwardIsReported(t *testing.T) {
	reported := make(chan error, 1)
	p := &Proxy{
		Session:  echoSession(t, alertingEdge(t, byte(alertAccessDenied))),
		Forwards: []Forward{{LocalAddr: "127.0.0.1:0", RemotePort: 22}},
		OnError:  func(err error) { reported <- err },
	}
	defer p.Session.Close()
	bound := make(chan string, 1)
	p.OnListen = func(_ Forward, addr string) { bound <- addr }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	c, err := net.Dial("tcp", <-bound)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	// A client that closes once the forward ends, as ssh does.
	go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
	select {
	case err := <-reported:
		assertRefusal(t, err, "denied this identity")
	case <-time.After(5 * time.Second):
		t.Fatal("a mid-stream refusal produced no error")
	}
}

// alertingEdge is a TLS 1.3 HTTP/2 edge that answers a CONNECT, echoes the
// first four bytes and then sends the fatal alert code on the connection,
// encrypted with the server's application traffic key as crypto/tls would.
func alertingEdge(t *testing.T, code byte) *httptest.Server {
	t.Helper()
	keys := &keyLog{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			return
		}
		_, _ = w.Write(buf)
		_ = rc.Flush()
		raw := r.Context().Value(rawConnKey{}).(*recordedConn)
		if err := raw.sendAlert(r.TLS.CipherSuite, keys.serverSecret(t), code); err != nil {
			t.Errorf("send alert: %v", err)
		}
		<-r.Context().Done()
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener = recordingListener{ln}
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, rawConnKey{}, c.(*tls.Conn).NetConn())
	}
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, KeyLogWriter: keys, SessionTicketsDisabled: true}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

type rawConnKey struct{}

// keyLog keeps the server application traffic secret from the key log.
type keyLog struct {
	mu     sync.Mutex
	secret []byte
}

func (k *keyLog) Write(line []byte) (int, error) {
	f := strings.Fields(string(line))
	if len(f) == 3 && f[0] == "SERVER_TRAFFIC_SECRET_0" {
		s, err := hex.DecodeString(f[2])
		if err != nil {
			return 0, err
		}
		k.mu.Lock()
		k.secret = s
		k.mu.Unlock()
	}
	return len(line), nil
}

func (k *keyLog) serverSecret(t *testing.T) []byte {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.secret == nil {
		t.Error("no server traffic secret in the key log")
	}
	return k.secret
}

type recordingListener struct{ net.Listener }

func (l recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordedConn{Conn: c}, nil
}

// recordedConn keeps every byte the server wrote, so sendAlert can count the
// records sealed with the application key and take the next sequence number.
type recordedConn struct {
	net.Conn
	mu  sync.Mutex
	out []byte
}

func (c *recordedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out = append(c.out, p...)
	return c.Conn.Write(p)
}

// sendAlert writes a fatal TLS 1.3 alert record (RFC 8446 section 5.2)
// sealed with the server application traffic secret.
func (c *recordedConn) sendAlert(suite uint16, secret []byte, code byte) error {
	aead, iv, err := trafficAEAD(suite, secret)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	nonce := func(seq uint64) []byte {
		n := bytes.Clone(iv)
		for i := range 8 {
			n[len(n)-1-i] ^= byte(seq >> (8 * i))
		}
		return n
	}
	// Records sealed with the handshake key fail to open with this one.
	var seq uint64
	for rest := c.out; len(rest) >= 5; {
		n := 5 + int(binary.BigEndian.Uint16(rest[3:5]))
		if n > len(rest) {
			break
		}
		rec := rest[:n]
		rest = rest[n:]
		if rec[0] == 23 {
			if _, err := aead.Open(nil, nonce(seq), rec[5:], rec[:5]); err == nil {
				seq++
			}
		}
	}
	inner := []byte{2, code, 21} // fatal, code, content type alert
	hdr := []byte{23, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(hdr[3:], uint16(len(inner)+aead.Overhead()))
	_, err = c.Conn.Write(aead.Seal(bytes.Clone(hdr), nonce(seq), inner, hdr))
	return err
}

// trafficAEAD derives the record key and IV of a TLS 1.3 traffic secret
// (RFC 8446 section 7.3).
func trafficAEAD(suite uint16, secret []byte) (cipher.AEAD, []byte, error) {
	h, keyLen := sha256.New, 16
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
	case tls.TLS_AES_256_GCM_SHA384:
		h, keyLen = sha512.New384, 32
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		keyLen = chacha20poly1305.KeySize
	default:
		return nil, nil, fmt.Errorf("cipher suite %#x", suite)
	}
	expand := func(label string, n int) ([]byte, error) {
		full := "tls13 " + label
		info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
		return hkdf.Expand(h, secret, string(append(info, 0)), n)
	}
	key, err := expand("key", keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err := expand("iv", 12)
	if err != nil {
		return nil, nil, err
	}
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		aead, err := chacha20poly1305.New(key)
		return aead, iv, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, iv, err
}

// The TLS 1.3 minimum is enforced at the handshake.
func TestConsumerRefusesATLS12Server(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := BaseTLSConfig(net.JoinHostPort(host, port), "")
	cfg.RootCAs = srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), cfg)
	if err == nil {
		conn.Close()
		t.Fatal("a TLS 1.2 server must be refused: the client certificate would go in the clear")
	}
	if !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// An edge that refuses the client certificate is reported with the device name
// and the next step. Under TLS 1.3 the handshake succeeds on the client and the
// alert arrives on the first request.
func TestRefusedClientCertificateIsReported(t *testing.T) {
	device := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	device.EnableHTTP2 = true
	// Requires a client certificate and trusts no CA, so every one is refused.
	device.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  x509.NewCertPool(),
		MinVersion: tls.VersionTLS13,
	}
	device.StartTLS()
	defer device.Close()

	cfg, err := BuildTLSConfig(writePEMBundle(t, t.TempDir(), "client.pem"), "", "", "gw-01.eu.localport.dev:443", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InsecureSkipVerify = true //nolint:gosec // test server

	reported := make(chan error, 1)
	p := &Proxy{
		Session: &Session{
			Device:    "gw-01.eu.localport.dev",
			Addr:      device.Listener.Addr().String(),
			TLSConfig: cfg,
		},
		Forwards: []Forward{{LocalAddr: "127.0.0.1:0", RemotePort: 22}},
		OnError: func(err error) {
			select {
			case reported <- err:
			default:
			}
		},
	}
	bound := make(chan string, 1)
	p.OnListen = func(_ Forward, addr string) { bound <- addr }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	client, err := net.Dial("tcp", <-bound)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer client.Close()

	select {
	case err := <-reported:
		assertRefusal(t, err, "localport identity list")
	case <-time.After(5 * time.Second):
		t.Fatal("a refused client certificate produced no error")
	}
}

// A failed request waits for the connection's read error, which can arrive
// after the write that failed.
func TestFirstReadErrorWaitsForTheReader(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	conn := newReadErrConn(tls.Client(client, &tls.Config{InsecureSkipVerify: true})) //nolint:gosec // no handshake completes

	go func() { _, _ = conn.Read(make([]byte, 1)) }()
	time.AfterFunc(100*time.Millisecond, func() { _ = server.Close() })

	if err := conn.firstReadError(5 * time.Second); err == nil {
		t.Fatal("want the read error that arrived after the call")
	}
	if err := (*readErrConn)(nil).firstReadError(time.Millisecond); err != nil {
		t.Fatalf("a replaced connection has no read error, got %v", err)
	}
}

// echoDevice stands in for the edge: an HTTP/2 server that answers CONNECT and
// echoes the stream.
func echoDevice(t *testing.T, http2 bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				_ = rc.Flush()
			}
			if err != nil {
				return
			}
		}
	}))
	srv.EnableHTTP2 = http2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func echoSession(t *testing.T, srv *httptest.Server) *Session {
	t.Helper()
	cfg, err := BuildTLSConfig(writePEMBundle(t, t.TempDir(), "client.pem"), "", "", "gw-01.eu.localport.dev:443", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.InsecureSkipVerify = true //nolint:gosec // test server
	s := &Session{Device: "gw-01.eu.localport.dev", TLSConfig: cfg}
	if srv != nil {
		s.Addr = srv.Listener.Addr().String()
	}
	return s
}

// A forward is a CONNECT stream on the session's HTTP/2 connection.
func TestSessionOpensAConnectStream(t *testing.T) {
	s := echoSession(t, echoDevice(t, true))
	defer s.Close()

	conn, err := s.Open(context.Background(), 22)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("echoed %q, want %q", got, "ping")
	}
}

// A server that ignores ALPN is refused rather than spoken to over HTTP/1.
func TestSessionRefusesAServerWithoutHTTP2(t *testing.T) {
	cert := echoDevice(t, false).TLS.Certificates
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()

	s := echoSession(t, nil)
	s.Addr = ln.Addr().String()
	defer s.Close()

	_, err = s.Open(context.Background(), 22)
	if err == nil {
		t.Fatal("a server without HTTP/2 must be refused")
	}
	if !strings.Contains(err.Error(), "did not accept HTTP/2") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
