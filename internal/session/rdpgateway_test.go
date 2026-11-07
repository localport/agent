//go:build linux || darwin

package session

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// golden returns a PDU of testdata/rdcleanpath.golden, encoded by
// ironrdp-rdcleanpath (testdata/rdcleanpath).
func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/rdcleanpath.golden")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(b)) {
		if n, h, ok := strings.Cut(strings.TrimSpace(line), " "); ok && n == name {
			pdu, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			return pdu
		}
	}
	t.Fatalf("no golden %q", name)
	return nil
}

// x224Confirm is a Connection Confirm TPKT selecting protocol, as the golden
// generator's.
func x224Confirm(protocol uint32) []byte {
	b := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, rdpNegResponse, 0x1f, 0x08, 0x00}
	return binary.LittleEndian.AppendUint32(b, protocol)
}

var (
	// x224Request asks for TLS and CredSSP.
	x224Request = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	// x224Failure is a Connection Confirm carrying RDP_NEG_FAILURE
	// HYBRID_REQUIRED_BY_SERVER.
	x224Failure = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, rdpNegFailure, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00}
	// x224NoNegotiation is a Connection Confirm with no negotiation
	// structure: Standard RDP Security.
	x224NoNegotiation = []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00}
)

// testRequest is an RDCleanPath request as a client may send it.
type testRequest struct {
	Version     int64  `asn1:"explicit,tag:0"`
	Destination string `asn1:"optional,explicit,utf8,tag:2"`
	ProxyAuth   string `asn1:"optional,explicit,utf8,tag:3"`
	ServerAuth  string `asn1:"optional,explicit,utf8,tag:4"`
	PCB         string `asn1:"optional,explicit,utf8,tag:5"`
	X224        []byte `asn1:"optional,explicit,tag:6"`
}

func marshalRequest(t *testing.T, r testRequest) []byte {
	t.Helper()
	b, err := asn1.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validRequest() testRequest {
	return testRequest{Version: rdcleanpathVersion, Destination: "localport-desktop", ProxyAuth: "localport", X224: x224Request}
}

// The agent's PDUs are byte for byte IronRDP's, and IronRDP's request
// parses.
func TestRDCleanPathMatchesIronRDP(t *testing.T) {
	resp, err := asn1.Marshal(rdcleanpathResponse{Version: rdcleanpathVersion, X224: x224Confirm(2),
		CertChain: [][]byte{[]byte("leaf-certificate-der"), []byte("issuer-der")}, ServerAddr: "192.168.1.20:3389"})
	if err != nil || !bytes.Equal(resp, golden(t, "response")) {
		t.Fatalf("response %x, %v; want %x", resp, err, golden(t, "response"))
	}
	nerr, err := asn1.Marshal(rdcleanpathResponse{Version: rdcleanpathVersion,
		Error: rdcleanpathError{Code: rdcleanpathNegotiationError}, X224: x224Confirm(2)})
	if err != nil || !bytes.Equal(nerr, golden(t, "negotiation_error")) {
		t.Fatalf("negotiation error %x, %v; want %x", nerr, err, golden(t, "negotiation_error"))
	}
	x224, err := parseRDCleanPathRequest(golden(t, "request"))
	if want := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00}; err != nil || !bytes.Equal(x224, want) {
		t.Fatalf("request x224 %x, %v; want %x", x224, err, want)
	}
}

func TestParseRDCleanPathRequest(t *testing.T) {
	big := validRequest()
	big.X224 = append(binary.BigEndian.AppendUint16([]byte{3, 0}, x224MaxPDU+1), make([]byte, x224MaxPDU-3)...)
	for name, tc := range map[string]struct {
		edit func(*testRequest)
		raw  []byte
		ok   bool
	}{
		"valid":            {ok: true},
		"no proxy_auth":    {edit: func(r *testRequest) { r.ProxyAuth = "" }, ok: true},
		"wrong version":    {edit: func(r *testRequest) { r.Version = 3389 }},
		"no destination":   {edit: func(r *testRequest) { r.Destination = "" }},
		"preconnection":    {edit: func(r *testRequest) { r.PCB = "pcb" }},
		"server_auth":      {edit: func(r *testRequest) { r.ServerAuth = "x" }},
		"vmconnect":        {edit: func(r *testRequest) { r.X224, r.PCB = nil, "vm" }},
		"tpkt length":      {edit: func(r *testRequest) { r.X224 = append([]byte(nil), x224Request[:18]...) }},
		"tpkt version":     {edit: func(r *testRequest) { r.X224 = append([]byte{2}, x224Request[1:]...) }},
		"x224 over bound":  {edit: func(r *testRequest) { *r = big }},
		"trailing bytes":   {raw: append(marshalRequest(t, validRequest()), 0)},
		"not a sequence":   {raw: append([]byte{0x31}, marshalRequest(t, validRequest())[1:]...)},
		"response field":   {raw: mustMarshal(t, rdcleanpathResponse{Version: rdcleanpathVersion, X224: x224Request, ServerAddr: "a"})},
		"out of tag order": {raw: reorderedRequest(t)},
	} {
		t.Run(name, func(t *testing.T) {
			pdu := tc.raw
			if pdu == nil {
				r := validRequest()
				if tc.edit != nil {
					tc.edit(&r)
				}
				pdu = marshalRequest(t, r)
			}
			x224, err := parseRDCleanPathRequest(pdu)
			var he *handshakeError
			switch {
			case tc.ok && (err != nil || !bytes.Equal(x224, x224Request)):
				t.Fatalf("parse: %x, %v", x224, err)
			case !tc.ok && (!errors.As(err, &he) || he.fault != faultMalformed || he.side != sideClient):
				t.Fatalf("parse: %v, want a malformed client error", err)
			}
		})
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// reorderedRequest puts the X.224 field before the destination.
func reorderedRequest(t *testing.T) []byte {
	t.Helper()
	field := func(tag int, v any) []byte {
		inner := mustMarshal(t, v)
		return mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
	}
	body := append(field(0, int64(rdcleanpathVersion)), field(6, x224Request)...)
	body = append(body, field(2, asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("d")})...)
	return mustMarshal(t, asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

func TestParseX224Confirm(t *testing.T) {
	for name, tc := range map[string]struct {
		confirm  []byte
		protocol uint32
		failed   bool
		bad      bool
	}{
		"ssl":            {confirm: x224Confirm(1), protocol: 1},
		"hybrid":         {confirm: x224Confirm(2), protocol: 2},
		"hybrid ex":      {confirm: x224Confirm(8), protocol: 8},
		"rdstls":         {confirm: x224Confirm(4), protocol: 4},
		"no negotiation": {confirm: x224NoNegotiation, protocol: 0},
		"failure":        {confirm: x224Failure, failed: true},
		"length indicator": {confirm: func() []byte {
			b := x224Confirm(2)
			b[4] = 0x0d
			return b
		}(), bad: true},
		"not a confirm": {confirm: func() []byte {
			b := x224Confirm(2)
			b[5] = 0xe0
			return b
		}(), bad: true},
		"negotiation length": {confirm: func() []byte {
			b := x224Confirm(2)
			b[13] = 0x09
			return b
		}(), bad: true},
		"negotiation type": {confirm: func() []byte {
			b := x224Confirm(2)
			b[11] = 0x01
			return b
		}(), bad: true},
	} {
		t.Run(name, func(t *testing.T) {
			protocol, failed, err := parseX224Confirm(tc.confirm)
			var he *handshakeError
			if tc.bad {
				if !errors.As(err, &he) || he.fault != faultMalformed || he.side != sideTarget {
					t.Fatalf("parse: %v, want a malformed target error", err)
				}
				return
			}
			if err != nil || protocol != tc.protocol || failed != tc.failed {
				t.Fatalf("parse: %d %v %v; want %d %v", protocol, failed, err, tc.protocol, tc.failed)
			}
		})
	}
}

func TestCutUTF8(t *testing.T) {
	for _, tc := range []struct {
		s    string
		n    int
		want string
	}{{"abc", 5, "abc"}, {"abc", 2, "ab"}, {"aé", 2, "a"}, {"aé", 3, "aé"}, {"日本", 4, "日"}} {
		if got := cutUTF8(tc.s, tc.n); got != tc.want {
			t.Fatalf("cutUTF8(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
		}
	}
}

// testCert is a self-signed target certificate.
func testCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(1900000000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// rdpTarget is a fake RDP server: it reads the X.224 request (handing it to
// requests), writes confirm, then runs after, which by default is a TLS
// server with cert echoing the plaintext.
type rdpTarget struct {
	*vncTarget
	requests chan []byte
}

func newRDPTarget(t *testing.T, cert tls.Certificate, confirm []byte, after func(net.Conn) error) *rdpTarget {
	t.Helper()
	r := &rdpTarget{requests: make(chan []byte, 4)}
	if after == nil {
		after = func(c net.Conn) error {
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err := tc.Handshake(); err != nil {
				return err
			}
			_, _ = io.Copy(tc, tc)
			return errors.New("session over")
		}
	}
	r.vncTarget = newScriptedTarget(t, func(c net.Conn) error {
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil {
			return err
		}
		rest := make([]byte, int(binary.BigEndian.Uint16(head[2:]))-4)
		if _, err := io.ReadFull(c, rest); err != nil {
			return err
		}
		r.requests <- append(head, rest...)
		if confirm == nil {
			_ = c.Close() // a target that drops the connection
			return errors.New("no confirm")
		}
		if _, err := c.Write(confirm); err != nil {
			return err
		}
		return after(c)
	})
	return r
}

func rdpFixture(t *testing.T, addr string, edit func(*ServerConfig)) *sshFixture {
	t.Helper()
	return newSSHFixture(t, func(c *ServerConfig) {
		c.Capabilities, c.Desktop, c.RDPTarget = []string{"desktop"}, []string{"rdp"}, addr
		c.DesktopKeys = &memKeys{}
		if edit != nil {
			edit(c)
		}
	})
}

func (f *sshFixture) rdpOpts() certOpts {
	o := f.defaults()
	o.kind, o.login = "rdp", desktopPrincipal
	return o
}

// openRDP opens the rdp channel and writes the bytes the client starts with.
func openRDP(t *testing.T, client *ssh.Client, first []byte) (ssh.Channel, <-chan *ssh.Request) {
	t.Helper()
	ch, reqs, err := openDesktopChannel(client, chanRDP)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := ch.Write(first); err != nil {
		t.Fatal(err)
	}
	return ch, reqs
}

// readResponse reads one DER RDCleanPath PDU from r and decodes it.
func readResponse(t *testing.T, r *bufio.Reader) rdcleanpathResponse {
	t.Helper()
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		t.Fatalf("read response: %v", err)
	}
	n := int(head[1])
	if n&0x80 != 0 {
		lb := make([]byte, n&0x7f)
		if _, err := io.ReadFull(r, lb); err != nil {
			t.Fatal(err)
		}
		head = append(head, lb...)
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}
	var resp rdcleanpathResponse
	if rest, err := asn1.Unmarshal(append(head, body...), &resp); err != nil || len(rest) != 0 {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// rdpKeyRequest waits for the agent's rdp key question and answers it.
func rdpKeyRequest(t *testing.T, reqs <-chan *ssh.Request, answer bool) rdpKeyInfo {
	t.Helper()
	select {
	case r, ok := <-reqs:
		var info rdpKeyInfo
		if !ok || r.Type != reqDesktopKey || !r.WantReply || ssh.Unmarshal(r.Payload, &info) != nil {
			t.Fatalf("want a key request, got %v %v", ok, r)
		}
		_ = r.Reply(answer, nil)
		return info
	case <-time.After(5 * time.Second):
		t.Fatal("no key request")
		return rdpKeyInfo{}
	}
}

// noRequestsThenClose fails on any channel request and waits for the close.
func noRequestsThenClose(t *testing.T, reqs <-chan *ssh.Request) {
	t.Helper()
	select {
	case r, ok := <-reqs:
		if ok {
			t.Fatalf("request %q", r.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel did not close")
	}
}

// On first use the agent relays the X.224 request unchanged, asks with the
// certificate's details, pins the SPKI on trust, and answers with the
// confirm, the chain and the target; the relay then carries plaintext, the
// bytes sent after the request first. The next connection asks pinned.
func TestRDPGatewayFirstUseAndMatch(t *testing.T) {
	cert := testCert(t, "desktop.test")
	leaf := cert.Leaf
	for _, protocol := range []uint32{rdpProtocolSSL, rdpProtocolHybrid, rdpProtocolHybridEx} {
		target := newRDPTarget(t, cert, x224Confirm(protocol), nil)
		addr := target.ln.Addr().String()
		keys := &memKeys{}
		f := rdpFixture(t, addr, func(c *ServerConfig) { c.DesktopKeys = keys })
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, append(marshalRequest(t, validRequest()), "early"...))
		if got := <-target.requests; !bytes.Equal(got, x224Request) {
			t.Fatalf("target got %x, want %x", got, x224Request)
		}
		spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		certSum, thumb := sha256.Sum256(leaf.Raw), sha1.Sum(leaf.Raw)
		want := rdpKeyInfo{SHA256: hex.EncodeToString(spki[:]), CertSHA256: hex.EncodeToString(certSum[:]),
			SHA1: hex.EncodeToString(thumb[:]), Subject: "CN=desktop.test", Issuer: "CN=desktop.test", SelfSigned: true,
			NotBefore: 1700000000, NotAfter: 1900000000}
		if info := rdpKeyRequest(t, reqs, true); info != want {
			t.Fatalf("key info %+v, want %+v", info, want)
		}
		r := bufio.NewReader(ch)
		resp := readResponse(t, r)
		if resp.Version != rdcleanpathVersion || !bytes.Equal(resp.X224, x224Confirm(protocol)) || len(resp.CertChain) != 1 ||
			!bytes.Equal(resp.CertChain[0], leaf.Raw) || resp.ServerAddr != addr || resp.Error != (rdcleanpathError{}) {
			t.Fatalf("response %+v", resp)
		}
		if _, err := ch.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		readFor(t, r, "earlyping")
		if k, held, _ := keys.Lookup("rdp", addr); !held || k != spki {
			t.Fatalf("pin %x %v, want %x", k, held, spki)
		}
		_ = ch.Close()
		waitClosed(t, client)

		if protocol == rdpProtocolHybrid {
			o := f.rdpOpts()
			o.serial = 43
			client = f.connect(t, o)
			ch, reqs = openRDP(t, client, marshalRequest(t, validRequest()))
			<-target.requests
			if info := rdpKeyRequest(t, reqs, true); !info.Pinned {
				t.Fatal("a pinned key was asked unpinned")
			}
			readResponse(t, bufio.NewReader(ch))
		}
	}
}

// A changed key ends without asking; a refusal and a store error end with
// their codes. Nothing from the target reaches the client in any of them.
func TestRDPGatewayKeyRefusals(t *testing.T) {
	cert := testCert(t, "desktop.test")
	for name, tc := range map[string]struct {
		keys   *memKeys
		ask    bool
		answer bool
		want   string
	}{
		"changed":     {keys: &memKeys{}, want: CloseDesktopKeyChanged},
		"rejected":    {keys: &memKeys{}, ask: true, want: CloseDesktopKeyRejected},
		"store error": {keys: &memKeys{err: errors.New("disk")}, want: CloseDesktopKeyUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			target := newRDPTarget(t, cert, x224Confirm(2), nil)
			if name == "changed" {
				tc.keys.pins = map[string][32]byte{"rdp " + target.ln.Addr().String(): {1}}
			}
			f := rdpFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.DesktopKeys = tc.keys })
			client := f.connect(t, f.rdpOpts())
			ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
			if tc.ask {
				rdpKeyRequest(t, reqs, tc.answer)
			}
			if reason := waitEndRequest(t, reqs); reason != tc.want {
				t.Fatalf("end %q, want %q", reason, tc.want)
			}
			if b := readAll(ch); len(b) != 0 {
				t.Fatalf("the client got %q", b)
			}
		})
	}
}

// A Negotiation Failure reaches the client as an RDCleanPath negotiation
// error carrying the confirm; Standard RDP Security and other protocols are
// refused with nothing sent.
func TestRDPGatewayNegotiation(t *testing.T) {
	cert := testCert(t, "desktop.test")
	t.Run("failure", func(t *testing.T) {
		target := newRDPTarget(t, cert, x224Failure, nil)
		f := rdpFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
		resp := readResponse(t, bufio.NewReader(ch))
		if resp.Error.Code != rdcleanpathNegotiationError || !bytes.Equal(resp.X224, x224Failure) || resp.ServerAddr != "" || resp.CertChain != nil {
			t.Fatalf("response %+v", resp)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseRDPNegotiationFailed {
			t.Fatalf("end %q", reason)
		}
	})
	for name, confirm := range map[string][]byte{"standard": x224NoNegotiation, "protocol 0": x224Confirm(0), "rdstls": x224Confirm(4)} {
		t.Run(name, func(t *testing.T) {
			target := newRDPTarget(t, cert, confirm, nil)
			f := rdpFixture(t, target.ln.Addr().String(), nil)
			client := f.connect(t, f.rdpOpts())
			ch, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
			if reason := waitEndRequest(t, reqs); reason != CloseRDPSecurityRefused {
				t.Fatalf("end %q", reason)
			}
			if b := readAll(ch); len(b) != 0 {
				t.Fatalf("the client got %q", b)
			}
		})
	}
}

// A target that answers TLS with something else ends rdp_tls_failed.
// A connection end while the gateway waits, for the target's TLS handshake
// or for the client's answer to the key question, closes the target and
// pins nothing.
func TestRDPGatewayEndDuringEachWait(t *testing.T) {
	cert := testCert(t, "desktop.test")
	for name, tc := range map[string]struct {
		handshake bool
		ask       bool
	}{
		"tls handshake": {handshake: true},
		"key question":  {ask: true},
	} {
		t.Run(name, func(t *testing.T) {
			var after func(net.Conn) error
			hello := make(chan struct{})
			if tc.handshake {
				after = func(c net.Conn) error {
					// Reads the ClientHello's first byte, then never answers.
					if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
						return err
					}
					close(hello)
					_, err := io.Copy(io.Discard, c)
					return err
				}
			}
			target := newRDPTarget(t, cert, x224Confirm(2), after)
			keys := &memKeys{}
			f := rdpFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.DesktopKeys = keys })
			client := f.connect(t, f.rdpOpts())
			_, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
			select {
			case <-target.requests:
			case <-time.After(5 * time.Second):
				t.Fatal("no X.224 request at the target")
			}
			if tc.handshake {
				select {
				case <-hello:
				case <-time.After(5 * time.Second):
					t.Fatal("no ClientHello at the target")
				}
			}
			if tc.ask {
				select {
				case r := <-reqs:
					if r == nil || r.Type != reqDesktopKey {
						t.Fatalf("request %v", r)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("no key request")
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := f.srv.Shutdown(ctx); err != nil {
				t.Fatalf("shutdown: %v", err)
			}
			target.waitClosed(t)
			if _, held, _ := keys.Lookup("rdp", target.ln.Addr().String()); held {
				t.Fatal("a key was pinned without an answer")
			}
		})
	}
}

func TestRDPGatewayTLSFailure(t *testing.T) {
	cert := testCert(t, "desktop.test")
	for name, after := range map[string]func(net.Conn) error{
		"not tls": func(c net.Conn) error {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return errors.New("not tls")
		},
		// A server limited to TLS 1.1 answers the TLS 1.2 minimum with a
		// protocol_version alert, which crypto/tls returns as a "remote error".
		"alert": func(c net.Conn) error {
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
			return tc.Handshake()
		},
		// A handshake record whose message type is unknown, in place of the
		// ServerHello: crypto/tls sends unexpected_message itself and returns
		// a "local error".
		"unexpected message": func(c net.Conn) error {
			if _, err := io.ReadFull(c, make([]byte, 5)); err != nil {
				return err
			}
			_, err := c.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0xff, 0x00, 0x00, 0x00})
			_, _ = io.Copy(io.Discard, c)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			target := newRDPTarget(t, tls.Certificate{}, x224Confirm(2), after)
			f := rdpFixture(t, target.ln.Addr().String(), nil)
			client := f.connect(t, f.rdpOpts())
			_, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
			if reason := waitEndRequest(t, reqs); reason != CloseRDPTLSFailed {
				t.Fatalf("end %q", reason)
			}
		})
	}
}

// Malformed, oversize and refused requests end desktop_handshake_invalid
// without reaching the target.
func TestRDPGatewayRefusedRequests(t *testing.T) {
	pcb := validRequest()
	pcb.PCB = "pcb"
	for name, first := range map[string][]byte{
		// The header alone claims one byte past the bound.
		"oversize":       {0x30, 0x82, byte((rdcleanpathMaxRequest - 3) >> 8), byte((rdcleanpathMaxRequest - 3) & 0xff)},
		"indefinite":     {0x30, 0x80},
		"not a sequence": {0x04, 0x01, 0x00},
		"preconnection":  marshalRequest(t, pcb),
	} {
		t.Run(name, func(t *testing.T) {
			target := newRDPTarget(t, tls.Certificate{}, x224Confirm(2), nil)
			f := rdpFixture(t, target.ln.Addr().String(), nil)
			client := f.connect(t, f.rdpOpts())
			_, reqs := openRDP(t, client, first)
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopHandshake {
				t.Fatalf("end %q", reason)
			}
			select {
			case r := <-target.requests:
				t.Fatalf("the target got %x", r)
			default:
			}
		})
	}
}

// The target closing before or within the confirm ends desktop_target_closed;
// a silent target ends desktop_handshake_timeout at its deadline.
func TestRDPGatewayTargetEnds(t *testing.T) {
	for name, tc := range map[string]struct {
		confirm []byte
		after   func(net.Conn) error
		want    string
	}{
		"closes after the request": {want: CloseDesktopTargetClosed},
		"short confirm":            {confirm: x224Confirm(2)[:8], after: func(c net.Conn) error { _ = c.Close(); return errors.New("closed") }, want: CloseDesktopTargetClosed},
		"silent": {confirm: []byte{}, after: func(c net.Conn) error {
			_, _ = io.Copy(io.Discard, c)
			return errors.New("silent")
		}, want: CloseDesktopHandshakeTimeout},
	} {
		t.Run(name, func(t *testing.T) {
			target := newRDPTarget(t, tls.Certificate{}, tc.confirm, tc.after)
			f := rdpFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.desktopCheckTimeout = 200 * time.Millisecond })
			client := f.connect(t, f.rdpOpts())
			_, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
			if reason := waitEndRequest(t, reqs); reason != tc.want {
				t.Fatalf("end %q, want %q", reason, tc.want)
			}
		})
	}
}

// An rdp connection dials the rdp target, never the vnc one.
func TestRDPDialsTheRDPTarget(t *testing.T) {
	vnc := newVNCTarget(t)
	rdp := newRDPTarget(t, testCert(t, "desktop.test"), x224Confirm(2), nil)
	f := rdpFixture(t, rdp.ln.Addr().String(), func(c *ServerConfig) {
		c.Desktop, c.VNCTarget = []string{"rdp", "vnc"}, vnc.ln.Addr().String()
	})
	client := f.connect(t, f.rdpOpts())
	_, reqs := openRDP(t, client, marshalRequest(t, validRequest()))
	<-rdp.requests
	rdpKeyRequest(t, reqs, false)
	select {
	case <-vnc.accepted:
		t.Fatal("the vnc target was dialed")
	default:
	}
}

// A client EOF during the handshake ends the connection "exited", with no
// end request, for both kinds.
func TestDesktopClientEOFDuringHandshake(t *testing.T) {
	t.Run("rdp", func(t *testing.T) {
		target := newRDPTarget(t, tls.Certificate{}, x224Confirm(2), nil)
		f := rdpFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.rdpOpts())
		ch, reqs := openRDP(t, client, marshalRequest(t, validRequest())[:5])
		_ = ch.CloseWrite()
		noRequestsThenClose(t, reqs)
		target.waitClosed(t)
		waitClosed(t, client)
	})
	t.Run("vnc", func(t *testing.T) {
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "RFB 003.008\n")
		_ = ch.CloseWrite()
		noRequestsThenClose(t, reqs)
		target.waitClosed(t)
		waitClosed(t, client)
	})
}

// waitClock is manualClock whose desktop client wait the test fires. With
// stopLate, a stop reports the timer already fired while nothing is
// delivered: the race in which the watcher sees the stop first.
type waitClock struct {
	manualClock
	stopLate bool
	armed    chan chan time.Time
}

func newWaitClock(stopLate bool) *waitClock {
	return &waitClock{stopLate: stopLate, armed: make(chan chan time.Time, 4)}
}

func (c *waitClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	if d != desktopClientWait {
		return c.manualClock.NewTimer(d)
	}
	ch := make(chan time.Time, 1)
	c.armed <- ch
	return ch, func() bool { return !c.stopLate && len(ch) == 0 }
}

// fire fires the next armed client wait.
func (c *waitClock) fire(t *testing.T) {
	t.Helper()
	select {
	case ch := <-c.armed:
		ch <- time.Now()
	case <-time.After(5 * time.Second):
		t.Fatal("no client wait armed")
	}
}

// The client wait ends a connection whose client stays silent, for both
// kinds; a stop that loses the race to the timer ends it too, before any
// key question.
func TestDesktopClientWait(t *testing.T) {
	cases := map[string]func(t *testing.T, clock *waitClock) (ssh.Channel, <-chan *ssh.Request){
		"rdp": func(t *testing.T, clock *waitClock) (ssh.Channel, <-chan *ssh.Request) {
			target := newRDPTarget(t, testCert(t, "desktop.test"), x224Confirm(2), nil)
			f := rdpFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
			client := f.connect(t, f.rdpOpts())
			ch, reqs, err := openDesktopChannel(client, chanRDP)
			if err != nil {
				t.Fatal(err)
			}
			return ch, reqs
		},
		"vnc": func(t *testing.T, clock *waitClock) (ssh.Channel, <-chan *ssh.Request) {
			target := newScriptedTarget(t, rfbServer("RFB 003.008\n", []byte{6}, 0, sendKeyThenFrame(rsaKey(2048, 7))))
			f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
			client := f.connect(t, f.vncOpts())
			ch, reqs, err := openDesktopChannel(client, chanVNC)
			if err != nil {
				t.Fatal(err)
			}
			return ch, reqs
		},
	}
	// finish sends the client's part up to the key question.
	finish := map[string]func(t *testing.T, ch ssh.Channel){
		"rdp": func(t *testing.T, ch ssh.Channel) {
			if _, err := ch.Write(marshalRequest(t, validRequest())); err != nil {
				t.Fatal(err)
			}
		},
		"vnc": func(t *testing.T, ch ssh.Channel) {
			readFor(t, ch, "RFB 003.008\n")
			_, _ = io.WriteString(ch, "RFB 003.008\n")
			readFor(t, ch, "\x01\x06")
			_, _ = ch.Write([]byte{6})
		},
	}
	for kind, open := range cases {
		t.Run(kind+" silent", func(t *testing.T) {
			clock := newWaitClock(false)
			_, reqs := open(t, clock)
			clock.fire(t)
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopHandshakeTimeout {
				t.Fatalf("end %q", reason)
			}
		})
		t.Run(kind+" stop race", func(t *testing.T) {
			clock := newWaitClock(true)
			ch, reqs := open(t, clock)
			finish[kind](t, ch)
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopHandshakeTimeout {
				t.Fatalf("end %q, want %q before any key question", reason, CloseDesktopHandshakeTimeout)
			}
		})
	}
}
