package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

// The prelude runs on a session stream before any frame (agent/docs/PROTOCOL.md
// "Resumable connections"). A first connect binds the connection to the
// client's certificate key and derives a static resume token from an X25519
// exchange; the token never crosses the wire. A resume proves the token with
// an HMAC over a transcript that holds the agent's fresh key, after the
// client verified the agent's host-key signature, so a relay learns nothing
// it could replay (the TLS 1.3 PSK binder model).
const (
	preludeVersion    = 2
	preludeMaxMessage = 16 << 10
	resumeHandleLen   = 16
	resumeTokenLabel  = "localport-resume-v1"
	// Signature contexts: the agent signs with the device host key, the client
	// with its certificate's key.
	agentSigContext  = "localport-resume-agent-v1"
	clientSigContext = "localport-resume-client-v1"
	// maxProofFailures failed resume proofs end the connection resume_refused.
	maxProofFailures = 3
)

// Status of an agent prelude reply.
const (
	statusOK      uint32 = 0
	statusRefused uint32 = 1
	statusBusy    uint32 = 2
	statusLost    uint32 = 3
)

// Reasons a resumable connection ends with or a resume is refused with.
const (
	CloseDetachTimeout = "detach_timeout"
	CloseResumeRefused = "resume_refused"
	CloseResumeLost    = "resume_lost"
	CloseResumeBusy    = "resume_busy"
)

// Prelude messages, x/crypto ssh wire encoding, each sent as a 4-byte
// big-endian length and the encoding. Sig and Proof fields are left empty in
// the transcript.
type helloMsg struct {
	Version   uint32 `sshtype:"160"`
	ClientKey []byte
	Cert      []byte
	Sig       []byte
}

type helloReplyMsg struct {
	Status   uint32 `sshtype:"161"`
	AgentKey []byte
	Handle   []byte
	// HostKey is the device host key in SSH wire form, so a client whose pin
	// differs can name the presented key.
	HostKey []byte
	Sig     []byte
}

// HostKeyMismatchError is a hello answered under another host key than the
// pinned one; Fingerprint is the presented key's SHA256 fingerprint.
type HostKeyMismatchError struct {
	Fingerprint string
}

func (e *HostKeyMismatchError) Error() string {
	return "session prelude: the device presented host key " + e.Fingerprint + ", not the pinned one"
}

// presentedKeyError names a presented host key that is not the pin.
func presentedKeyError(raw []byte) error {
	key, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return errPrelude
	}
	return &HostKeyMismatchError{Fingerprint: ssh.FingerprintSHA256(key)}
}

type resumeMsg struct {
	Version   uint32 `sshtype:"162"`
	Handle    []byte
	ClientKey []byte
	Position  uint64
	// Close asks the agent to end the connection once the resume is proven,
	// as a received closeTag does, instead of installing the stream.
	Close bool
	Cert  []byte
	Sig   []byte
}

type resumeReplyMsg struct {
	Status   uint32 `sshtype:"163"`
	AgentKey []byte
	Position uint64
	Sig      []byte
}

type proofMsg struct {
	Proof []byte `sshtype:"164"`
}

type proofReplyMsg struct {
	Status uint32 `sshtype:"165"`
}

// ResumeError is a prelude refused by the agent. Code is one of
// CloseResumeRefused, CloseResumeBusy, CloseResumeLost.
type ResumeError struct {
	Code string
}

func (e *ResumeError) Error() string { return "session resume refused: " + e.Code }

// Retryable reports whether a later resume may succeed.
func (e *ResumeError) Retryable() bool { return e.Code == CloseResumeBusy }

func statusError(status uint32) error {
	switch status {
	case statusOK:
		return nil
	case statusBusy:
		return &ResumeError{Code: CloseResumeBusy}
	case statusLost:
		return &ResumeError{Code: CloseResumeLost}
	}
	return &ResumeError{Code: CloseResumeRefused}
}

// errPrelude is a malformed or unexpected prelude message.
var errPrelude = errors.New("session prelude: malformed message")

func writePrelude(w io.Writer, msg any) error {
	payload := ssh.Marshal(msg)
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(payload)), uint32(len(payload)))
	_, err := w.Write(append(out, payload...))
	return err
}

func readPreludeRaw(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > preludeMaxMessage {
		return nil, errPrelude
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readPrelude(r io.Reader, msg any) error {
	payload, err := readPreludeRaw(r)
	if err != nil {
		return err
	}
	if err := ssh.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("%w: %v", errPrelude, err)
	}
	return nil
}

// transcript is SHA-256 over the messages in order, each encoded with its
// signature field empty.
func transcript(msgs ...any) []byte {
	h := sha256.New()
	for _, m := range msgs {
		h.Write(ssh.Marshal(m))
	}
	return h.Sum(nil)
}

func sigData(context string, th []byte) []byte {
	return append(append([]byte(context), 0), th...)
}

func signPrelude(signer ssh.Signer, context string, th []byte) ([]byte, error) {
	sig, err := signer.Sign(rand.Reader, sigData(context, th))
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(sig), nil
}

func verifyPrelude(key ssh.PublicKey, context string, th, raw []byte) bool {
	var sig ssh.Signature
	if err := ssh.Unmarshal(raw, &sig); err != nil {
		return false
	}
	return key.Verify(sigData(context, th), &sig) == nil
}

// resumeToken derives the connection's static resume token from the first
// connect's X25519 shared secret, salted with its transcript.
func resumeToken(priv *ecdh.PrivateKey, peer []byte, th []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, errPrelude
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, errPrelude
	}
	return hkdf.Key(sha256.New, secret, th, resumeTokenLabel, sha256.Size)
}

func resumeProof(token, th []byte) []byte {
	m := hmac.New(sha256.New, token)
	m.Write(th)
	return m.Sum(nil)
}

// noSig returns a copy of each message with its Sig empty, for the
// transcript.
func (m helloMsg) noSig() helloMsg             { m.Sig = nil; return m }
func (m helloReplyMsg) noSig() helloReplyMsg   { m.Sig = nil; return m }
func (m resumeMsg) noSig() resumeMsg           { m.Sig = nil; return m }
func (m resumeReplyMsg) noSig() resumeReplyMsg { m.Sig = nil; return m }

// ClientResumable is the client end of a resumable connection: the conn SSH
// runs on and what a resume needs. Hello creates it; the caller runs
// Conn.Attach on the stream and, after a stream ends Detached, Resume on a
// new one.
type ClientResumable struct {
	Conn    *ResumableConn
	key     []byte
	hostKey ssh.PublicKey
	handle  []byte
	token   []byte
}

// certOf returns the certificate of a certificate signer (ssh.NewCertSigner),
// which signs with the certificate's key.
func certOf(signer ssh.Signer) (*ssh.Certificate, error) {
	cert, ok := signer.PublicKey().(*ssh.Certificate)
	if !ok {
		return nil, errors.New("session prelude: the signer holds no certificate")
	}
	return cert, nil
}

// Hello runs a first connect's prelude on stream. signer is the certificate
// signer SSH userauth will present: its certificate is the one the edge
// admitted the stream with. hostKey is the pinned device host key.
func Hello(stream io.ReadWriter, signer ssh.Signer, hostKey ssh.PublicKey) (*ClientResumable, error) {
	cert, err := certOf(signer)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hello := helloMsg{Version: preludeVersion, ClientKey: priv.PublicKey().Bytes(), Cert: cert.Marshal()}
	if hello.Sig, err = signPrelude(signer, clientSigContext, transcript(hello.noSig())); err != nil {
		return nil, err
	}
	if err := writePrelude(stream, hello); err != nil {
		return nil, err
	}
	var reply helloReplyMsg
	if err := readPrelude(stream, &reply); err != nil {
		return nil, err
	}
	if err := statusError(reply.Status); err != nil {
		return nil, err
	}
	if len(reply.Handle) != resumeHandleLen {
		return nil, errPrelude
	}
	if !bytes.Equal(reply.HostKey, hostKey.Marshal()) {
		return nil, presentedKeyError(reply.HostKey)
	}
	th := transcript(hello.noSig(), reply.noSig())
	if !verifyPrelude(hostKey, agentSigContext, th, reply.Sig) {
		return nil, errors.New("session prelude: the agent's signature does not verify with the pinned host key")
	}
	token, err := resumeToken(priv, reply.AgentKey, th)
	if err != nil {
		return nil, err
	}
	return &ClientResumable{Conn: NewResumableConn(), key: cert.Key.Marshal(), hostKey: hostKey, handle: reply.Handle, token: token}, nil
}

// Resume runs a resume's prelude on stream with signer, the certificate
// signer of the resume certificate the edge admitted it with (same key as the
// first connect), and returns the agent's received position for Conn.Attach.
// Call it only while Conn is detached. A *ResumeError is the agent's refusal.
func (c *ClientResumable) Resume(stream io.ReadWriter, signer ssh.Signer) (uint64, error) {
	return c.resume(stream, signer, false)
}

// resume runs a resume's prelude; with closeConn it is a close resume: the
// agent ends the connection once the proof verifies and a position outside
// its send buffer does not matter. The caller ends Conn after a close resume.
func (c *ClientResumable) resume(stream io.ReadWriter, signer ssh.Signer, closeConn bool) (uint64, error) {
	cert, err := certOf(signer)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(cert.Key.Marshal(), c.key) {
		return 0, errors.New("session prelude: the resume certificate is not for the connection's key")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return 0, err
	}
	msg := resumeMsg{Version: preludeVersion, Handle: c.handle, ClientKey: priv.PublicKey().Bytes(),
		Position: c.Conn.Received(), Close: closeConn, Cert: cert.Marshal()}
	if msg.Sig, err = signPrelude(signer, clientSigContext, transcript(msg.noSig())); err != nil {
		return 0, err
	}
	if err := writePrelude(stream, msg); err != nil {
		return 0, err
	}
	var reply resumeReplyMsg
	if err := readPrelude(stream, &reply); err != nil {
		return 0, err
	}
	if err := statusError(reply.Status); err != nil {
		return 0, err
	}
	th := transcript(msg.noSig(), reply.noSig())
	if len(reply.AgentKey) != 32 || !verifyPrelude(c.hostKey, agentSigContext, th, reply.Sig) {
		return 0, errors.New("session prelude: the agent's resume signature does not verify with the pinned host key")
	}
	if !closeConn && !c.Conn.CanResumeFrom(reply.Position) {
		c.Conn.End(ErrResumeLost)
		return 0, &ResumeError{Code: CloseResumeLost}
	}
	if err := writePrelude(stream, proofMsg{Proof: resumeProof(c.token, th)}); err != nil {
		return 0, err
	}
	var done proofReplyMsg
	if err := readPrelude(stream, &done); err != nil {
		return 0, err
	}
	if err := statusError(done.Status); err != nil {
		return 0, err
	}
	return reply.Position, nil
}

// readClientPrelude reads a stream's first prelude message: a hello or a
// resume.
func readClientPrelude(stream net.Conn) (*helloMsg, *resumeMsg, error) {
	payload, err := readPreludeRaw(stream)
	if err != nil {
		return nil, nil, err
	}
	switch payload[0] {
	case 160:
		var m helloMsg
		if err := ssh.Unmarshal(payload, &m); err != nil || m.Version != preludeVersion || len(m.ClientKey) != 32 {
			return nil, nil, errPrelude
		}
		return &m, nil, nil
	case 162:
		var m resumeMsg
		if err := ssh.Unmarshal(payload, &m); err != nil || m.Version != preludeVersion ||
			len(m.ClientKey) != 32 || len(m.Handle) != resumeHandleLen {
			return nil, nil, errPrelude
		}
		return nil, &m, nil
	}
	return nil, nil, errPrelude
}
