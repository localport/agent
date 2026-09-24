package access

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
		403: "port 502 is open",
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

func TestLoadAccessConfigRefusesIncompleteEntries(t *testing.T) {
	cases := map[string]string{
		"version 2":   "version: 2\naccess: []\n",
		"no devices":  "version: 1\naccess: []\n",
		"no forward":  "version: 1\naccess:\n  - device: gw.example.com\n",
		"no device":   "version: 1\naccess:\n  - forward: [\"502\"]\n",
		"file and id": "version: 1\naccess:\n  - device: gw.example.com\n    forward: [\"502\"]\n    identity: x\n    p12: /tmp/x.p12\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "access.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := LoadAccessConfig(path); err == nil {
				t.Fatal("want the file refused")
			}
		})
	}
}

// A certificate alert carries no reason. The message names the next step
// without guessing one.
func TestStreamErrorNamesTheNextStep(t *testing.T) {
	cases := map[string]string{
		"remote error: tls: bad certificate":     "identity list",
		"remote error: tls: certificate expired": "localport login",
	}
	for alert, want := range cases {
		got := streamError("gw-01.eu.localport.dev", errors.New(alert)).Error()
		if !strings.Contains(got, want) {
			t.Fatalf("%q -> %q, want it to mention %q", alert, got, want)
		}
		if !strings.Contains(got, "gw-01.eu.localport.dev") {
			t.Fatalf("%q -> %q, want the device named", alert, got)
		}
	}
	if msg := streamError("gw-01", io.ErrUnexpectedEOF).Error(); !strings.Contains(msg, "ended") {
		t.Fatalf("an unmapped failure reads as %q", msg)
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

// classify matches wrapped errors, which os.IsNotExist does not unwrap.
func TestBuildTLSConfigNamesFileErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	_, err := BuildTLSConfig(missing, "", "", "gw-01.eu.localport.dev:443", "")
	if err == nil {
		t.Fatal("want an error for a missing PEM file")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Fatalf("error should name the cause, got %q", err)
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

// Revoked certificates and withdrawn grants get specific messages.
func TestStreamErrorExplainsEveryCertificateAlert(t *testing.T) {
	// crypto/tls alertText strings, wrapped in net.OpError as for a
	// post-handshake alert.
	cases := []struct{ alert, want string }{
		{"tls: bad certificate", "refused this certificate"},
		{"tls: unknown certificate", "refused this certificate"},
		{"tls: certificate required", "refused this certificate"},
		{"tls: unknown certificate authority", "refused this certificate"},
		{"tls: revoked certificate", "cannot be renewed"},
		{"tls: access denied", "denied this identity"},
		{"tls: expired certificate", "run `localport login` again"},
	}
	for _, tc := range cases {
		err := streamError("gw-01.eu.localport.dev", errors.New("remote error: "+tc.alert))
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q produced %q, want it to mention %q", tc.alert, err, tc.want)
		}
		if !strings.Contains(err.Error(), "gw-01.eu.localport.dev") {
			t.Errorf("%q: error should name the device, got %q", tc.alert, err)
		}
	}

	// Other alerts keep the generic message.
	other := streamError("gw-01.eu.localport.dev", errors.New("connection reset by peer"))
	if !strings.Contains(other.Error(), "ended") {
		t.Fatalf("unrecognised failure = %q", other)
	}
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
		for _, want := range []string{"gw-01.eu.localport.dev", "refused this certificate", "localport identity list"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal must mention %q, got %q", want, err)
			}
		}
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
