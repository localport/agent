package session

import (
	"bytes"
	"context"
	"crypto/sha1" // the Windows thumbprint a person compares; the pin is SHA-256
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Reasons an rdp connection's gateway ends it with.
const (
	// CloseRDPNegotiationFailed: the target answered the X.224 request with
	// a Negotiation Failure.
	CloseRDPNegotiationFailed = "rdp_negotiation_failed"
	// CloseRDPSecurityRefused: the target selected Standard RDP Security or a
	// protocol other than TLS, CredSSP or CredSSP with Early User Auth.
	CloseRDPSecurityRefused = "rdp_security_refused"
	// CloseRDPTLSFailed: the TLS handshake with the target failed on an alert
	// or a protocol error.
	CloseRDPTLSFailed = "rdp_tls_failed"
)

const (
	// rdcleanpathVersion is the RDCleanPath PDU version IronRDP speaks.
	rdcleanpathVersion = 3390
	// rdcleanpathMaxRequest bounds the client's RDCleanPath request PDU.
	rdcleanpathMaxRequest = 16 << 10
	// rdcleanpathNegotiationError is the RDCleanPath error code of a
	// Negotiation Failure, which carries the target's confirm.
	rdcleanpathNegotiationError = 2
	// x224MaxPDU bounds the X.224 Connection Request and Confirm TPKTs, as
	// Devolutions Gateway does.
	x224MaxPDU = 512
	// tpktHeaderLen is a TPKT header: version 3, reserved, 16-bit length.
	tpktHeaderLen = 4
	// x224ConfirmMinLen is a TPKT header and a Connection Confirm without
	// a negotiation structure (MS-RDPBCGR 2.2.1.2).
	x224ConfirmMinLen = tpktHeaderLen + 7
	// RDP_NEG_RSP and RDP_NEG_FAILURE types and their fixed length.
	rdpNegResponse, rdpNegFailure = 0x02, 0x03
	rdpNegLen                     = 8
	// Protocols the gateway accepts as the target's selection: TLS, CredSSP,
	// CredSSP with Early User Authorization Result.
	rdpProtocolSSL, rdpProtocolHybrid, rdpProtocolHybridEx = 1, 2, 8
	// rdpMaxCertName bounds the subject and issuer in the key question.
	rdpMaxCertName = 512
)

// Context tags of the RDCleanPath PDU fields (ironrdp-rdcleanpath
// RDCleanPathPdu); a request carries only version, destination,
// proxy_auth and x224_connection_pdu.
const (
	rdcpTagVersion     = 0
	rdcpTagDestination = 2
	rdcpTagProxyAuth   = 3
	rdcpTagX224        = 6
)

// rdcleanpathResponse is the RDCleanPath PDU the gateway sends: a response
// (x224, chain, server_addr) or a negotiation error (error, x224). Every
// field is EXPLICIT-tagged; strings are UTF8String, the only string type
// the client decodes.
type rdcleanpathResponse struct {
	Version    int64            `asn1:"explicit,tag:0"`
	Error      rdcleanpathError `asn1:"optional,explicit,tag:1"`
	X224       []byte           `asn1:"optional,explicit,tag:6"`
	CertChain  [][]byte         `asn1:"optional,explicit,tag:7"`
	ServerAddr string           `asn1:"optional,explicit,utf8,tag:9"`
}

type rdcleanpathError struct {
	Code int64 `asn1:"explicit,tag:0"`
}

// rdpKeyInfo is the desktop-key@localport.io payload of an rdp target: the
// leaf certificate's SPKI SHA-256 (the pinned key) and whether it is pinned,
// then what a person compares it with: the certificate's SHA-256 and SHA-1
// thumbprints, subject and issuer (RFC 4514, at most rdpMaxCertName bytes),
// whether it is self-signed, and its validity in Unix seconds.
type rdpKeyInfo struct {
	SHA256     string
	Pinned     bool
	CertSHA256 string
	SHA1       string
	Subject    string
	Issuer     string
	SelfSigned bool
	NotBefore  uint64
	NotAfter   uint64
}

// rdpGateway is the RDCleanPath gateway of an rdp connection: it reads the
// client's request, relays its X.224 Connection Request unchanged, checks
// the confirm, runs TLS with the target, pins the leaf's key, and answers
// with the RDCleanPath response; the relay then carries the TLS plaintext
// through the rdp filter. Nothing from the target reaches the client before
// the pin decision.
type rdpGateway struct {
	*desktopHandshake
	// tls is the target's TLS session once the gateway succeeded.
	tls *tls.Conn
	// protocol is the security protocol the target's confirm selected.
	protocol uint32
}

// run runs the gateway. It returns the reason to end the connection with,
// or "" to relay over g.tls; err is a handshakeError or the connection's
// end (handshakeOutcome maps it).
func (g *rdpGateway) run(ctx context.Context) (string, error) {
	defer func() { _ = g.target.SetDeadline(time.Time{}) }()
	x224, err := g.readRequest()
	if err != nil {
		return "", err
	}
	if err := g.clientWaitDone(); err != nil {
		return "", err
	}
	if err := g.writeTarget(x224); err != nil {
		return "", err
	}
	confirm, err := g.readConfirm()
	if err != nil {
		return "", err
	}
	protocol, failed, err := parseX224Confirm(confirm)
	switch {
	case err != nil:
		return "", err
	case failed:
		pdu, err := asn1.Marshal(rdcleanpathResponse{Version: rdcleanpathVersion,
			Error: rdcleanpathError{Code: rdcleanpathNegotiationError}, X224: confirm})
		if err != nil {
			return "", err
		}
		if err := g.writeClient(pdu); err != nil {
			return "", err
		}
		return CloseRDPNegotiationFailed, nil
	case protocol != rdpProtocolSSL && protocol != rdpProtocolHybrid && protocol != rdpProtocolHybridEx:
		g.c.s.log("session: rdp target %s selected protocol %d", g.addr, protocol)
		return CloseRDPSecurityRefused, nil
	}

	_ = g.target.SetDeadline(time.Now().Add(g.timeout))
	// The pinned SPKI below replaces chain verification; no server name is sent.
	tc := tls.Client(g.target, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := tc.Handshake(); err != nil {
		if !isTLSProtocolError(err) {
			return "", targetIOError(err)
		}
		g.c.s.log("session: rdp target %s TLS: %v", g.addr, err)
		return CloseRDPTLSFailed, nil
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		g.c.s.log("session: rdp target %s sent no certificate", g.addr)
		return CloseRDPTLSFailed, nil
	}
	leaf := certs[0]
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	reason, err := g.trust(ctx, sum, func(pinned bool) []byte { return ssh.Marshal(newRDPKeyInfo(leaf, sum, pinned)) })
	if reason != "" || err != nil {
		return reason, err
	}

	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	pdu, err := asn1.Marshal(rdcleanpathResponse{Version: rdcleanpathVersion, X224: confirm, CertChain: chain, ServerAddr: g.addr})
	if err != nil {
		return "", err
	}
	if err := g.writeClient(pdu); err != nil {
		return "", err
	}
	g.tls, g.protocol = tc, protocol
	return "", nil
}

// readRequest reads the client's one RDCleanPath request PDU, at most
// rdcleanpathMaxRequest bytes, and returns its X.224 Connection Request.
// Bytes after the PDU stay in the client reader for the relay.
func (g *rdpGateway) readRequest() ([]byte, error) {
	head, err := g.readClient(2)
	if err != nil {
		return nil, err
	}
	if head[0] != 0x30 {
		return nil, malformed(sideClient, "RDCleanPath request is not a SEQUENCE")
	}
	n := int(head[1])
	if n&0x80 != 0 {
		// Long form; two length bytes cover the bound, DER forbids more.
		k := n & 0x7f
		if k == 0 || k > 2 {
			return nil, malformed(sideClient, "RDCleanPath request length form %#x", head[1])
		}
		lb, err := g.readClient(k)
		if err != nil {
			return nil, err
		}
		head = append(head, lb...)
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	if len(head)+n > rdcleanpathMaxRequest {
		return nil, malformed(sideClient, "RDCleanPath request of %d bytes", len(head)+n)
	}
	body, err := g.readClient(n)
	if err != nil {
		return nil, err
	}
	return parseRDCleanPathRequest(append(head, body...))
}

// parseRDCleanPathRequest checks a DER RDCleanPath request PDU: version
// 3390, a destination, an X.224 Connection Request that is one TPKT of at
// most x224MaxPDU bytes, and no other field than proxy_auth. A
// preconnection blob, server_auth or the VMConnect form (no X.224) is
// refused. The destination and proxy_auth are never read.
func parseRDCleanPathRequest(pdu []byte) ([]byte, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(pdu, &seq)
	if err != nil || len(rest) != 0 || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, malformed(sideClient, "RDCleanPath request is not one DER SEQUENCE")
	}
	fields := map[int][]byte{}
	last := -1
	for b := seq.Bytes; len(b) > 0; {
		var f asn1.RawValue
		if b, err = asn1.Unmarshal(b, &f); err != nil {
			return nil, malformed(sideClient, "RDCleanPath request field: %v", err)
		}
		if f.Class != asn1.ClassContextSpecific || !f.IsCompound || f.Tag <= last {
			return nil, malformed(sideClient, "RDCleanPath request field out of form or order")
		}
		switch f.Tag {
		case rdcpTagVersion, rdcpTagDestination, rdcpTagProxyAuth, rdcpTagX224:
		default:
			return nil, malformed(sideClient, "RDCleanPath request carries field [%d]", f.Tag)
		}
		last, fields[f.Tag] = f.Tag, f.Bytes
	}
	var version int64
	if !unmarshalOne(fields[rdcpTagVersion], &version) || version != rdcleanpathVersion {
		return nil, malformed(sideClient, "RDCleanPath request version")
	}
	if _, ok := fields[rdcpTagDestination]; !ok {
		return nil, malformed(sideClient, "RDCleanPath request without destination")
	}
	var x224 []byte
	if !unmarshalOne(fields[rdcpTagX224], &x224) {
		return nil, malformed(sideClient, "RDCleanPath request without an X.224 Connection Request")
	}
	if len(x224) < tpktHeaderLen || len(x224) > x224MaxPDU || x224[0] != 3 || int(binary.BigEndian.Uint16(x224[2:4])) != len(x224) {
		return nil, malformed(sideClient, "X.224 Connection Request is not one TPKT of at most %d bytes", x224MaxPDU)
	}
	return x224, nil
}

// unmarshalOne decodes b as exactly one DER value into v.
func unmarshalOne(b []byte, v any) bool {
	rest, err := asn1.Unmarshal(b, v)
	return err == nil && len(rest) == 0
}

// readConfirm reads the target's X.224 Connection Confirm: one TPKT of at
// least x224ConfirmMinLen and at most x224MaxPDU bytes.
func (g *rdpGateway) readConfirm() ([]byte, error) {
	head, err := g.readTarget(g.target, tpktHeaderLen)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(head[2:4]))
	if head[0] != 3 || n < x224ConfirmMinLen || n > x224MaxPDU {
		return nil, malformed(sideTarget, "X.224 Connection Confirm TPKT of %d bytes", n)
	}
	body, err := g.readTarget(g.target, n-tpktHeaderLen)
	if err != nil {
		return nil, err
	}
	return append(head, body...), nil
}

// parseX224Confirm reads a Connection Confirm TPKT: the selected protocol
// of its RDP_NEG_RSP (0, Standard RDP Security, when it has none), or
// failed for an RDP_NEG_FAILURE.
func parseX224Confirm(confirm []byte) (protocol uint32, failed bool, err error) {
	x := confirm[tpktHeaderLen:]
	if int(x[0]) != len(x)-1 || x[1]&0xf0 != 0xd0 {
		return 0, false, malformed(sideTarget, "not an X.224 Connection Confirm")
	}
	neg := x[7:]
	switch {
	case len(neg) == 0:
		return 0, false, nil
	case len(neg) != rdpNegLen || binary.LittleEndian.Uint16(neg[2:4]) != rdpNegLen:
		return 0, false, malformed(sideTarget, "X.224 negotiation structure of %d bytes", len(neg))
	case neg[0] == rdpNegResponse:
		return binary.LittleEndian.Uint32(neg[4:8]), false, nil
	case neg[0] == rdpNegFailure:
		return 0, true, nil
	}
	return 0, false, malformed(sideTarget, "X.224 negotiation type %#x", neg[0])
}

// isTLSProtocolError reports whether a TLS handshake error is an alert or a
// protocol error from the target, rather than a deadline, EOF or I/O error.
func isTLSProtocolError(err error) bool {
	var alert tls.AlertError
	var record tls.RecordHeaderError
	var op *net.OpError
	switch {
	case errors.As(err, &alert), errors.As(err, &record):
		return true
	// crypto/tls reports an alert the target sent, or one it sent itself on a
	// protocol violation, as a net.OpError with these operations (its alert
	// type is unexported; tls.AlertError wraps it only on QUIC connections).
	case errors.As(err, &op) && (op.Op == "remote error" || op.Op == "local error"):
		return true
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe), errors.As(err, new(*net.OpError)):
		return false
	}
	return true
}

// newRDPKeyInfo describes the target's leaf certificate for the key
// question.
func newRDPKeyInfo(leaf *x509.Certificate, spki [32]byte, pinned bool) rdpKeyInfo {
	cert := sha256.Sum256(leaf.Raw)
	thumb := sha1.Sum(leaf.Raw)
	return rdpKeyInfo{
		SHA256:     hex.EncodeToString(spki[:]),
		Pinned:     pinned,
		CertSHA256: hex.EncodeToString(cert[:]),
		SHA1:       hex.EncodeToString(thumb[:]),
		Subject:    cutUTF8(leaf.Subject.String(), rdpMaxCertName),
		Issuer:     cutUTF8(leaf.Issuer.String(), rdpMaxCertName),
		SelfSigned: bytes.Equal(leaf.RawSubject, leaf.RawIssuer),
		NotBefore:  unixSeconds(leaf.NotBefore),
		NotAfter:   unixSeconds(leaf.NotAfter),
	}
}

// cutUTF8 cuts s to at most n bytes without splitting a UTF-8 sequence.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// unixSeconds is t in Unix seconds, 0 before 1970.
func unixSeconds(t time.Time) uint64 {
	if s := t.Unix(); s > 0 {
		return uint64(s)
	}
	return 0
}
