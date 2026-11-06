// Package session serves remote access sessions on a device. Each session
// stream from the device's session mux carries one SSH connection: Server
// runs an x/crypto/ssh server on it with the device key as host key, admits
// the client by its SSH user certificate (signed by a session CA key, for the
// serial the edge admitted, for this device, for a login the local config
// enables), and serves its session channels through the root session
// launcher: a terminal on a PTY, or a command (exec). It records the
// connection when the certificate asks for it.
package session

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
)

// Reasons a connection ends with, written to its open channels' stderr and
// recorded; the edge records the stream's end.
const (
	CloseIdle     = "idle"
	CloseShutdown = "shutdown"
	// CloseConfigChanged ends the sessions of a device whose local config
	// entry a reload changed or removed.
	CloseConfigChanged = "config_changed"
	// CloseExited: the last channel of a terminal connection closed.
	CloseExited = "exited"
)

const (
	maxSessions = 8
	// maxChannels bounds the session channels of one connection; a terminal
	// connection has one.
	maxChannels = 4
	// handshakeTimeout bounds the SSH key exchange and userauth from the
	// stream's start.
	handshakeTimeout  = 10 * time.Second
	keyRefreshTimeout = 3 * time.Second
	idleTimeout       = 30 * time.Minute
	// serverVersion is the SSH identification string.
	serverVersion = "SSH-2.0-localport"
)

// Permissions extension keys carrying the admitted identity from userauth to
// the channel handlers. Nothing else is read from a connection.
const (
	permKind    = "kind"
	permSubject = "subject"
	permRecPol  = "rec-policy"
	permRecPub  = "rec-pub"
	permCert    = "cert"
	// permFwdLocal and permFwdRemote are present when the certificate
	// permits that forward direction.
	permFwdLocal  = "fwd-local"
	permFwdRemote = "fwd-remote"
)

// ServerConfig is one device's session server configuration. Capabilities,
// Logins and Desktop are the device's local config; nothing from the network
// widens them.
type ServerConfig struct {
	// Prefix is the device prefix certificates must name.
	Prefix string
	// Certificate returns the certificate, with its key, of the device's last
	// acknowledged registration: its key is the SSH host key, and
	// certificates are bound to its public key.
	Certificate func() (*tls.Certificate, bool)
	// CAKeys returns the session CA keys user certificates are signed by.
	CAKeys func() []ed25519.PublicKey
	// RefreshKeys fetches the CA key set and recording key; called once for
	// a certificate of an unknown CA key and once for a rec naming a key
	// other than the held one.
	RefreshKeys func(ctx context.Context) error
	// RecordingKey returns the held team recording public key and its
	// SHA-256; ok is false when none is held. Nil holds none.
	RecordingKey func() (key []byte, sum [sha256.Size]byte, ok bool)
	// Capabilities are the enabled config.Capability values.
	Capabilities []string
	Logins       []string
	// PasswordLogins are the Logins that log on with the login's password
	// (Windows): userauth asks it by keyboard-interactive after the
	// certificate, and every channel's launcher request carries it.
	PasswordLogins []string
	// Desktop lists the configured desktop targets: rdp, vnc.
	Desktop []string
	// OnEvent receives one line per notable failure. Optional.
	OnEvent func(string)
	// Uploader delivers the recordings of certificates with rec; nil leaves
	// recording unavailable: Strict connections are closed before any
	// channel and Best effort ones run unrecorded.
	Uploader *recording.Uploader
	// Identifier is the device's identity (identity.Ref.Identity), kept in
	// each recording's spool metadata.
	Identifier string
	// Device names the device's local config entry (identity.Ref.String()),
	// which the launcher authorizes each session against.
	Device string
	// Launcher starts sessions; nil is the launcher socket or pipe.
	Launcher Launcher

	// clock replaces the wall clock for validity and idle checks. Tests set it.
	clock clock
}

// clock is the time source of the validity and idle checks. NewTimer returns
// the timer's channel and a stop function.
type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) (<-chan time.Time, func() bool)
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) NewTimer(d time.Duration) (<-chan time.Time, func() bool) {
	t := time.NewTimer(d)
	return t.C, t.Stop
}

// Server serves the session streams of one device. It implements
// tunnel.SessionHandler: Shutdown ends every connection holding a session
// slot with CloseShutdown, aborts handshakes in progress, refuses streams
// arriving while it runs, and leaves the server usable for the next control
// session once it returns.
type Server struct {
	cfg ServerConfig
	// launcher serves the channels; nil when this build serves none.
	launcher Launcher

	// mu guards the fields below and every decision on them.
	mu       sync.Mutex
	closing  int // Shutdown calls in progress
	sessions int // slots taken, at most maxSessions
	// forwards counts the forward channels of every connection, at most
	// maxDeviceForwards.
	forwards int
	handlers map[*handler]struct{}
	// conns holds every live resumable connection by its resume handle.
	conns map[string]*resumable
	// drained is closed when handlers becomes empty while Shutdown waits.
	drained chan struct{}
}

// handler is one Serve call (its prelude and attached stream) or one
// connection (its SSH handshake and run), whichever Shutdown must stop.
type handler struct {
	// abort ends the handler's handshake at once: a Serve call's stream
	// deadline, a connection's ResumableConn.
	abort func()
	// stop is closed by Shutdown, after stopReason is set. stopped,
	// stopReason and handshaking are guarded by mu; stopReason is read
	// without it once stop is closed, as it is never written again.
	stop        chan struct{}
	stopped     bool
	stopReason  string
	handshaking bool
}

// resumable is one connection's resume state. The fields after ended are
// guarded by Server.mu.
type resumable struct {
	rc      *ResumableConn
	handle  string
	token   []byte
	subject string
	kind    string
	// certKey is the certificate key the first connect bound the connection
	// to; userauth and every resume must present it.
	certKey []byte
	// serial is the serial of the certificate that admitted the first connect.
	serial uint64
	// ended delivers an end decided outside run: detach timeout, a resume
	// refused or lost.
	ended chan string

	// streamGen counts attaches; a detach timer runs only for the latest one.
	streamGen int
	resuming  bool
	failures  int
	expired   bool
	removed   bool
	stopTimer func()
	// mark queues a marker on every recording of the connection; set by run.
	mark func(label string)
}

// endWith ends the connection with reason unless an end is already queued.
func (e *resumable) endWith(reason string) {
	select {
	case e.ended <- reason:
	default:
	}
}

var (
	errConnEnded        = errors.New("session: connection ended")
	errHandshakeTimeout = errors.New("session: SSH handshake timed out")
)

// detachTimeout bounds how long a connection waits detached for a resume.
const detachTimeout = 5 * time.Minute

// closeFlushTimeout bounds how long an ended connection's last bytes and
// closeTag may take to leave on its attached stream.
const closeFlushTimeout = 5 * time.Second

// NewServer returns the session server of one device.
func NewServer(cfg ServerConfig) *Server {
	if cfg.clock == nil {
		cfg.clock = wallClock{}
	}
	return &Server{cfg: cfg, launcher: launcherFor(cfg.Launcher), handlers: map[*handler]struct{}{}, conns: map[string]*resumable{}}
}

// LiveSessions returns the number of streams holding a session slot.
func (s *Server) LiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

// RecordingClientUp makes this device's recordings that wait for a session
// mux due at once.
func (s *Server) RecordingClientUp() {
	if s.cfg.Uploader != nil {
		s.cfg.Uploader.ClientUp(s.cfg.Identifier)
	}
}

func (s *Server) log(format string, args ...any) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(fmt.Sprintf(format, args...))
	}
}

// Serve runs one session stream to its end: a first connect starts an SSH
// connection on a ResumableConn, a resume attaches the stream to a detached
// one. id is the stream's session id (the access row id; a first connect's
// recordings name it) and serial the certificate serial the edge admitted.
// Serve returns when the stream ends; the connection outlives it while it
// waits detached for a resume. The caller closes stream after Serve returns.
func (s *Server) Serve(stream net.Conn, id [16]byte, serial uint64) {
	h := &handler{stop: make(chan struct{}), handshaking: true, abort: func() { _ = stream.SetDeadline(time.Now()) }}
	s.register(h)
	defer s.unregister(h)
	defer func() {
		if r := recover(); r != nil {
			s.log("session: handler panic: %v", r)
			_ = stream.Close()
		}
	}()
	_ = stream.SetDeadline(time.Now().Add(handshakeTimeout))
	hello, resume, err := readClientPrelude(stream)
	if err != nil {
		s.log("session: prelude: %v", err)
		return
	}
	if hello != nil {
		s.serveNew(h, stream, hello, id, serial)
		return
	}
	s.serveResume(h, stream, resume, serial)
}

// hostIdentity is the device's SSH host key and the Device certificates must
// name, from its last acknowledged registration.
func (s *Server) hostIdentity() (ssh.Signer, Device, error) {
	cert, ok := s.cfg.Certificate()
	if !ok || len(cert.Certificate) == 0 {
		return nil, Device{}, fmt.Errorf("no acknowledged registration to serve sessions with")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, Device{}, fmt.Errorf("the device key cannot sign")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, Device{}, fmt.Errorf("device certificate: %w", err)
		}
	}
	hostKey, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, Device{}, fmt.Errorf("host key: %w", err)
	}
	return hostKey, Device{Prefix: s.cfg.Prefix, SPKISHA256: SPKIHash(leaf.RawSubjectPublicKeyInfo)}, nil
}

// parsePreludeCert parses a prelude's certificate wire form.
func parsePreludeCert(raw []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, refuseCert("prelude certificate: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok || len(cert.ValidPrincipals) != 1 {
		return nil, refuseCert("prelude certificate: not a certificate with one principal")
	}
	return cert, nil
}

// serveNew runs a first connect: it admits the certificate the client signed
// the hello with, takes a session slot, answers under the host key and
// starts the connection, then runs the stream until it ends.
func (s *Server) serveNew(h *handler, stream net.Conn, hello *helloMsg, id [16]byte, serial uint64) {
	refuse := func(format string, args ...any) {
		s.log("session: first connect refused: "+format, args...)
		_ = writePrelude(stream, helloReplyMsg{Status: statusRefused})
	}
	host, device, err := s.hostIdentity()
	if err != nil {
		refuse("%v", err)
		return
	}
	cert, err := parsePreludeCert(hello.Cert)
	if err != nil {
		refuse("%v", err)
		return
	}
	adm, err := s.admit(cert, cert.ValidPrincipals[0], device, serial)
	if err != nil {
		refuse("%v", err)
		return
	}
	if !verifyPrelude(cert.Key, clientSigContext, transcript(hello.noSig()), hello.Sig) {
		refuse("the hello signature does not verify with the certificate's key")
		return
	}
	if !s.takeSlot(h) {
		refuse("no session slot")
		return
	}
	started := false
	defer func() {
		if !started {
			s.releaseSlot()
		}
	}()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		refuse("%v", err)
		return
	}
	handle := make([]byte, resumeHandleLen)
	_, _ = rand.Read(handle) // crypto/rand.Read never returns an error
	reply := helloReplyMsg{Status: statusOK, AgentKey: priv.PublicKey().Bytes(), Handle: handle, HostKey: host.PublicKey().Marshal()}
	th := transcript(hello.noSig(), reply.noSig())
	token, err := resumeToken(priv, hello.ClientKey, th)
	if err != nil {
		refuse("%v", err)
		return
	}
	if reply.Sig, err = signPrelude(host, agentSigContext, th); err != nil {
		refuse("host key signature: %v", err)
		return
	}
	if err := writePrelude(stream, reply); err != nil || !s.endHandshake(h) {
		return
	}
	_ = stream.SetDeadline(time.Time{})

	e := &resumable{rc: NewResumableConn(), handle: string(handle), token: token, subject: adm.Subject, kind: adm.Kind,
		certKey: cert.Key.Marshal(), serial: serial, ended: make(chan string, 1)}
	ch := &handler{stop: make(chan struct{}), handshaking: true, abort: func() { e.rc.End(errConnEnded) }}
	if !s.addConn(e, ch) {
		return
	}
	started = true
	go s.serveConn(ch, e, id, serial, cert.Key)
	s.attach(e, stream, 0)
}

// serveResume runs a resume: the handle's connection, a resume certificate
// for its original serial, subject and key signed by that key, a fresh
// host-key-signed reply, then the token proof, before any byte is resent.
func (s *Server) serveResume(h *handler, stream net.Conn, m *resumeMsg, serial uint64) {
	refuse := func(status uint32, format string, args ...any) {
		s.log("session: resume refused: "+format, args...)
		_ = writePrelude(stream, resumeReplyMsg{Status: status})
	}
	host, device, err := s.hostIdentity()
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	e, status := s.beginResume(string(m.Handle))
	if status != statusOK {
		refuse(status, "the connection is gone, resuming or shutting down")
		return
	}
	defer s.endResume(e)
	cert, err := parsePreludeCert(m.Cert)
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	adm, err := s.withCARefresh(cert, func() (*admission, error) {
		return verifyResumeCert(cert, s.caKeys(), device, serial, e.serial, s.cfg.clock.Now())
	})
	switch {
	case err != nil:
		refuse(statusRefused, "%v", err)
		return
	case adm.Subject != e.subject || adm.Kind != e.kind || !bytes.Equal(cert.Key.Marshal(), e.certKey):
		refuse(statusRefused, "the resume certificate is for another subject, kind or key")
		return
	case !verifyPrelude(cert.Key, clientSigContext, transcript(m.noSig()), m.Sig):
		refuse(statusRefused, "the resume signature does not verify with the certificate's key")
		return
	}
	// A resume for a live stream detaches it first, which settles positions.
	e.rc.Detach()
	if !e.rc.CanResumeFrom(m.Position) {
		refuse(statusLost, "position %d is outside the send buffer", m.Position)
		e.endWith(CloseResumeLost)
		return
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	reply := resumeReplyMsg{Status: statusOK, AgentKey: priv.PublicKey().Bytes(), Position: e.rc.Received()}
	th := transcript(m.noSig(), reply.noSig())
	if reply.Sig, err = signPrelude(host, agentSigContext, th); err != nil {
		refuse(statusRefused, "host key signature: %v", err)
		return
	}
	if err := writePrelude(stream, reply); err != nil {
		return
	}
	var proof proofMsg
	if err := readPrelude(stream, &proof); err != nil {
		return
	}
	if !hmac.Equal(proof.Proof, resumeProof(e.token, th)) {
		s.log("session: resume refused: the token proof does not verify")
		_ = writePrelude(stream, proofReplyMsg{Status: statusRefused})
		if s.proofFailed(e) >= maxProofFailures {
			e.endWith(CloseResumeRefused)
		}
		return
	}
	if !s.endHandshake(h) {
		return
	}
	_ = stream.SetDeadline(time.Time{})
	mark, ok := s.resumed(e)
	if !ok {
		_ = writePrelude(stream, proofReplyMsg{Status: statusLost})
		return
	}
	if err := writePrelude(stream, proofReplyMsg{Status: statusOK}); err != nil {
		return
	}
	if mark != nil {
		mark(markerAttach)
	}
	s.attach(e, stream, m.Position)
}

// attach runs stream as e's stream and, when it ends Detached and no newer
// stream took over, starts the detach timer.
func (s *Server) attach(e *resumable, stream net.Conn, peerReceived uint64) {
	s.mu.Lock()
	e.streamGen++
	gen := e.streamGen
	e.stopTimerLocked()
	s.mu.Unlock()
	if e.rc.Attach(stream, peerReceived) != Detached {
		return
	}
	s.mu.Lock()
	if e.streamGen != gen || e.removed {
		s.mu.Unlock()
		return
	}
	fire, stop := s.cfg.clock.NewTimer(detachTimeout)
	cancel := make(chan struct{})
	e.stopTimer = func() {
		stop()
		close(cancel)
	}
	mark := e.mark
	s.mu.Unlock()
	go func() {
		select {
		case <-fire:
			s.mu.Lock()
			live := e.streamGen == gen && !e.removed && !e.resuming
			if live {
				e.expired = true
			}
			s.mu.Unlock()
			if live {
				e.endWith(CloseDetachTimeout)
			}
		case <-cancel:
		}
	}()
	if mark != nil {
		mark(markerDetach)
	}
}

func (e *resumable) stopTimerLocked() {
	if e.stopTimer != nil {
		e.stopTimer()
		e.stopTimer = nil
	}
}

// addConn registers a started connection and its handler unless Shutdown is
// running.
func (s *Server) addConn(e *resumable, h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing > 0 {
		return false
	}
	s.handlers[h] = struct{}{}
	s.conns[e.handle] = e
	return true
}

// beginResume claims handle's connection for one resume: statusLost when it
// is gone, statusBusy while another resume runs, statusRefused during
// Shutdown.
func (s *Server) beginResume(handle string) (*resumable, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.conns[handle]
	switch {
	case e == nil || e.removed || e.expired:
		return nil, statusLost
	case s.closing > 0:
		return nil, statusRefused
	case e.resuming:
		return nil, statusBusy
	}
	e.resuming = true
	return e, statusOK
}

func (s *Server) endResume(e *resumable) {
	s.mu.Lock()
	e.resuming = false
	s.mu.Unlock()
}

func (s *Server) proofFailed(e *resumable) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.failures++
	return e.failures
}

// resumed reports whether e can take the resumed stream (it did not end or
// expire meanwhile) and returns its marker function.
func (s *Server) resumed(e *resumable) (func(string), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.removed || e.expired {
		return nil, false
	}
	return e.mark, true
}

// serveConn runs one connection: the SSH handshake on its ResumableConn,
// bounded by handshakeTimeout, then run. It owns the session slot serveNew
// took and removes the connection when it ends.
func (s *Server) serveConn(h *handler, e *resumable, id [16]byte, serial uint64, certKey ssh.PublicKey) {
	defer s.releaseSlot()
	defer s.removeConn(e, h)
	defer func() {
		if r := recover(); r != nil {
			s.log("session: connection panic: %v", r)
		}
	}()
	handshake := time.AfterFunc(handshakeTimeout, func() { e.rc.End(errHandshakeTimeout) })
	secret := &connSecret{}
	defer secret.clear()
	cfg, err := s.serverConfig(serial, secret, certKey)
	if err != nil {
		handshake.Stop()
		s.log("session: %v", err)
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(e.rc, cfg)
	handshake.Stop()
	if !s.endHandshake(h) || err != nil {
		if err != nil {
			s.log("session: SSH handshake or userauth failed: %v", err)
		}
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	defer conn.Close()
	s.run(h, conn, chans, reqs, admissionOf(conn.Permissions), uuidText(id), secret.password, e)
}

// removeConn forgets an ended connection: no resume finds it, its detach
// timer stops, its last bytes get closeFlushTimeout to leave on an attached
// stream, and then the conn is dropped.
func (s *Server) removeConn(e *resumable, h *handler) {
	s.mu.Lock()
	delete(s.conns, e.handle)
	e.removed = true
	e.stopTimerLocked()
	s.mu.Unlock()
	_ = e.rc.Close()
	select {
	case <-e.rc.Done():
	case <-time.After(closeFlushTimeout):
	}
	e.rc.End(errConnEnded)
	s.unregister(h)
}

// connSecret holds one connection's login password (a password login): set
// by the keyboard-interactive step, copied into each channel's launcher
// request, zeroed when the connection ends. The copy inside x/crypto's
// answer strings cannot be zeroed.
type connSecret struct {
	password []byte
}

func (c *connSecret) clear() { clear(c.password) }

// passwordPrompt is the one keyboard-interactive prompt of a password login.
const passwordPrompt = "Windows password: "

// serverConfig is one connection's SSH server configuration. Its callbacks
// keep no state across connections: the identity is built in
// VerifiedPublicKeyCallback, after possession of the certificate's key is
// proven, and returned as the connection's Permissions. For a password login
// that step is a partial success whose only next method is one
// keyboard-interactive prompt, so the prompt exists only after a verified
// certificate; its answer goes to secret. Userauth must present certKey, the
// key the prelude bound the connection to.
func (s *Server) serverConfig(serial uint64, secret *connSecret, certKey ssh.PublicKey) (*ssh.ServerConfig, error) {
	hostKey, device, err := s.hostIdentity()
	if err != nil {
		return nil, err
	}
	bound := certKey.Marshal()
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM},
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
		},
		ServerVersion: serverVersion,
		MaxAuthTries:  3,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, refuseCert("a plain key, not a certificate")
			}
			if !bytes.Equal(cert.Key.Marshal(), bound) {
				return nil, refuseCert("a certificate for another key than the prelude's")
			}
			return &ssh.Permissions{}, nil
		},
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			adm, err := s.admit(key.(*ssh.Certificate), meta.User(), device, serial)
			if err != nil {
				s.log("session: userauth refused: %v", err)
				return nil, err
			}
			perms := adm.permissions()
			if !slices.Contains(s.cfg.PasswordLogins, meta.User()) {
				return perms, nil
			}
			return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
				KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
					answers, err := client("", "", []string{passwordPrompt}, []bool{false})
					if err != nil {
						return nil, err
					}
					if len(answers) != 1 || answers[0] == "" || len(answers[0]) > launcher.MaxPassword {
						return nil, refuseCert("the password answer is empty or too long")
					}
					secret.clear()
					secret.password = []byte(answers[0])
					return perms, nil
				},
			}}
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg, nil
}

// admit verifies cert (refreshing the CA keys once for an unknown CA) and
// applies the local config: the kind enabled and served by this build, the
// login enabled, and a recording key that matches.
func (s *Server) admit(cert *ssh.Certificate, user string, device Device, serial uint64) (*admission, error) {
	adm, err := s.withCARefresh(cert, func() (*admission, error) {
		return verifyCert(cert, user, s.caKeys(), device, serial, s.cfg.clock.Now())
	})
	if err != nil {
		return nil, err
	}
	switch {
	case !s.kindEnabled(adm.Kind):
		return nil, refuseCert("kind %q is not enabled on this device", adm.Kind)
	case adm.Kind != "terminal" && adm.Kind != "ssh" && adm.Kind != "files":
		return nil, refuseCert("kind %q is not served by this agent", adm.Kind)
	case s.launcher == nil:
		return nil, refuseCert("this build serves no session")
	case !slices.Contains(s.cfg.Logins, adm.Login):
		return nil, refuseCert("login %q is not enabled on this device", adm.Login)
	case adm.Rec != nil && !s.recordingKeyMatches(adm.Rec.PubSHA256):
		return nil, refuseCert("the recording key is not the held team key")
	}
	return adm, nil
}

// withCARefresh runs verify, and once more after a CA key refresh when it
// failed for a certificate signed by no held CA key.
func (s *Server) withCARefresh(cert *ssh.Certificate, verify func() (*admission, error)) (*admission, error) {
	adm, err := verify()
	if err != nil && s.cfg.RefreshKeys != nil && !signedByCA(cert, s.caKeys()) {
		ctx, cancel := context.WithTimeout(context.Background(), keyRefreshTimeout)
		if rerr := s.cfg.RefreshKeys(ctx); rerr != nil {
			s.log("session: CA key refresh for an unknown CA key: %v", rerr)
		}
		cancel()
		adm, err = verify()
	}
	return adm, err
}

func (s *Server) caKeys() []ed25519.PublicKey {
	if s.cfg.CAKeys == nil {
		return nil
	}
	return s.cfg.CAKeys()
}

// permissions carries a into the connection's Permissions.
func (a *admission) permissions() *ssh.Permissions {
	ext := map[string]string{permKind: a.Kind, permSubject: a.Subject, permCert: base64.RawURLEncoding.EncodeToString(a.Cert)}
	if a.Rec != nil {
		ext[permRecPol], ext[permRecPub] = a.Rec.Policy, a.Rec.PubSHA256
	}
	if a.ForwardLocal {
		ext[permFwdLocal] = ""
	}
	if a.ForwardRemote {
		ext[permFwdRemote] = ""
	}
	return &ssh.Permissions{Extensions: ext}
}

// admissionOf reads the identity userauth stored; Login is the conn's user,
// which userauth checked against the certificate's principal.
func admissionOf(p *ssh.Permissions) *admission {
	ext := p.Extensions
	a := &admission{Kind: ext[permKind], Subject: ext[permSubject]}
	a.Cert, _ = base64.RawURLEncoding.DecodeString(ext[permCert])
	if pol, ok := ext[permRecPol]; ok {
		a.Rec = &certRec{Policy: pol, PubSHA256: ext[permRecPub]}
	}
	_, a.ForwardLocal = ext[permFwdLocal]
	_, a.ForwardRemote = ext[permFwdRemote]
	return a
}

// recordingKeyMatches reports whether the held recording key hashes to want
// (unpadded base64url), refreshing the keys once when it does not.
func (s *Server) recordingKeyMatches(want string) bool {
	if s.heldRecordingKeyIs(want) {
		return true
	}
	if s.cfg.RefreshKeys == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), keyRefreshTimeout)
	if err := s.cfg.RefreshKeys(ctx); err != nil {
		s.log("session: key refresh for a recording key mismatch: %v", err)
	}
	cancel()
	return s.heldRecordingKeyIs(want)
}

func (s *Server) heldRecordingKeyIs(want string) bool {
	if s.cfg.RecordingKey == nil {
		return false
	}
	_, sum, ok := s.cfg.RecordingKey()
	return ok && base64.RawURLEncoding.EncodeToString(sum[:]) == want
}

// kindEnabled maps a certificate kind to the capability that enables it:
// terminal and ssh need terminal, files needs files, rdp and vnc need desktop
// and their configured target.
func (s *Server) kindEnabled(kind string) bool {
	switch kind {
	case "terminal", "ssh":
		return slices.Contains(s.cfg.Capabilities, "terminal")
	case "files":
		return slices.Contains(s.cfg.Capabilities, "files")
	case "rdp", "vnc":
		return slices.Contains(s.cfg.Capabilities, "desktop") && slices.Contains(s.cfg.Desktop, kind)
	}
	return false
}

func (s *Server) register(h *handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[h] = struct{}{}
}

func (s *Server) unregister(h *handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.handlers, h)
	if len(s.handlers) == 0 && s.drained != nil {
		close(s.drained)
		s.drained = nil
	}
}

// endHandshake ends h's handshake, after which Shutdown ends the connection
// through h.stop. It reports false when Shutdown aborted the handshake. The
// caller clears its own deadline.
func (s *Server) endHandshake(h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.stopped {
		return false
	}
	h.handshaking = false
	return true
}

// takeSlot takes one of the maxSessions slots unless Shutdown is running or
// has stopped h.
func (s *Server) takeSlot(h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing > 0 || h.stopped || s.sessions >= maxSessions {
		return false
	}
	s.sessions++
	return true
}

func (s *Server) releaseSlot() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions--
}

// Shutdown stops every Serve call and waits for them or ctx. A connection
// gets CloseShutdown; a handshake in progress is aborted. Serve calls after
// it returns are served.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.shutdown(ctx, CloseShutdown)
}

// ShutdownConfigChanged is Shutdown for a device whose local config entry
// changed: connections end with CloseConfigChanged.
func (s *Server) ShutdownConfigChanged(ctx context.Context) error {
	return s.shutdown(ctx, CloseConfigChanged)
}

func (s *Server) shutdown(ctx context.Context, reason string) error {
	s.mu.Lock()
	s.closing++
	for h := range s.handlers {
		if h.stopped {
			continue
		}
		h.stopped = true
		h.stopReason = reason
		close(h.stop)
		if h.handshaking {
			// Ends the handshake at once; endHandshake then refuses it.
			h.abort()
		}
	}
	var drained chan struct{}
	if len(s.handlers) > 0 {
		if s.drained == nil {
			s.drained = make(chan struct{})
		}
		drained = s.drained
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.closing--
		s.mu.Unlock()
	}()
	if drained == nil {
		return nil
	}
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// conn is the state of one admitted connection that run shares with its
// channel goroutines.
type conn struct {
	s   *Server
	adm *admission
	// sessionID is the connection's session id in UUID text form; each
	// recorded channel's recording names it.
	sessionID string
	login     string
	// password is a password login's password (connSecret), nil otherwise;
	// each channel's launcher request gets its own copy.
	password []byte

	lastActivity atomic.Int64

	// fwd serves the connection's port forwards.
	fwd *forwarder
	// failed receives the reason of a failure that ends the connection (a
	// Strict forwards recording that failed).
	failed chan string

	mu sync.Mutex
	// open counts the channels accepted and not yet closed; served counts
	// every channel accepted. ended is set once the connection's end is
	// decided; no channel is accepted after it.
	open     int
	served   int
	ended    bool
	channels map[*channel]struct{}
	// allClosed receives once when a terminal connection's channel closed.
	allClosed chan struct{}
}

func (c *conn) active() { c.lastActivity.Store(c.s.cfg.clock.Now().UnixNano()) }

// fail ends the connection with reason unless its end is already decided.
func (c *conn) fail(reason string) {
	select {
	case c.failed <- reason:
	default:
	}
}

// run serves an admitted connection until its first recorded end: the client
// closing it, the idle timeout, a Shutdown, the channel of a terminal
// connection closing (a failed Strict recording ends its own channel), or a
// failed Strict forwards recording, or an end e queues (detach timeout, a
// resume refused or lost). It then writes the reason to every open channel's
// stderr (a detached conn is dropped first, so nothing waits for a stream),
// ends the forwards, closes the connection and joins the channels and
// forwards.
func (s *Server) run(h *handler, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, adm *admission, sessionID string, password []byte, e *resumable) {
	c := &conn{s: s, adm: adm, sessionID: sessionID, login: sc.User(), password: password,
		channels: map[*channel]struct{}{}, allClosed: make(chan struct{}, 1), failed: make(chan string, 1)}
	var wg sync.WaitGroup
	c.fwd = newForwarder(c, sc, &wg)
	s.mu.Lock()
	e.mark = c.markRecordings
	s.mu.Unlock()
	c.active()
	clientDone := make(chan struct{})
	wg.Go(func() {
		defer close(clientDone)
		c.accept(chans, &wg)
	})
	wg.Go(func() {
		// Global requests, answered in order: keepalives count as activity;
		// the remote forwarding requests are served when allowed, every
		// other request is refused.
		for r := range reqs {
			c.active()
			ok, payload := c.fwd.globalRequest(r)
			if r.WantReply {
				_ = r.Reply(ok, payload)
			}
		}
	})

	fire, stopTimer := s.cfg.clock.NewTimer(idleTimeout)
	var reason string
wait:
	for {
		select {
		case <-clientDone:
			break wait
		case <-c.allClosed:
			reason = CloseExited
			break wait
		case <-h.stop:
			reason = h.stopReason
			break wait
		case reason = <-c.failed:
			break wait
		case reason = <-e.ended:
			break wait
		case <-fire:
			idle := s.cfg.clock.Now().Sub(time.Unix(0, c.lastActivity.Load()))
			if idle >= idleTimeout {
				reason = CloseIdle
				break wait
			}
			fire, stopTimer = s.cfg.clock.NewTimer(idleTimeout - idle)
		}
	}
	stopTimer()
	if !e.rc.Attached() {
		e.rc.End(errConnEnded)
	}
	c.end(reason)
	_ = sc.Close()
	wg.Wait()
	// After every forward recorded its close.
	c.fwd.finish()
}

// end decides the connection's end and ends every open channel, telling the
// client why on its stderr when there is a reason.
func (c *conn) end(reason string) {
	c.mu.Lock()
	c.ended = true
	open := make([]*channel, 0, len(c.channels))
	for ch := range c.channels {
		open = append(open, ch)
	}
	c.mu.Unlock()
	for _, ch := range open {
		ch.end(reason)
	}
	c.fwd.end()
}

// markRecordings queues a marker on every open recording of the connection:
// each started channel's and the forwards'.
func (c *conn) markRecordings(label string) {
	c.mu.Lock()
	open := slices.Collect(maps.Keys(c.channels))
	forwards := c.fwd.rec
	c.mu.Unlock()
	for _, ch := range open {
		ch.mu.Lock()
		rec := ch.rec
		ch.mu.Unlock()
		rec.marker(label)
	}
	forwards.marker(label)
}

// accept serves the connection's channel opens: session channels, at most
// maxChannels open and one in all on a terminal connection, and the local
// port forwarding channels (forward.go, their own bounds). On a recorded
// connection every session channel opens its own recording.
func (c *conn) accept(chans <-chan ssh.NewChannel, wg *sync.WaitGroup) {
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
		case chanDirectTCPIP, chanDirectStreamLocal:
			c.fwd.local(nc)
			continue
		default:
			_ = nc.Reject(ssh.Prohibited, "only session and port forwarding channels are served")
			continue
		}
		c.mu.Lock()
		single := c.adm.Kind == "terminal"
		if c.ended || c.open >= maxChannels || (single && c.served >= 1) {
			c.mu.Unlock()
			_ = nc.Reject(ssh.ResourceShortage, "channel limit reached")
			continue
		}
		c.open++
		c.served++
		c.mu.Unlock()
		sch, creqs, err := nc.Accept()
		if err != nil {
			c.channelClosed(nil)
			continue
		}
		ch := &channel{c: c, ch: sch, halted: make(chan struct{})}
		c.mu.Lock()
		c.channels[ch] = struct{}{}
		c.mu.Unlock()
		wg.Go(func() {
			defer c.channelClosed(ch)
			ch.serve(creqs)
		})
	}
}

// channelClosed forgets ch; the last channel of a terminal or files
// connection ends it.
func (c *conn) channelClosed(ch *channel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.channels, ch)
	c.open--
	if c.open == 0 && (c.adm.Kind == "terminal" || c.adm.Kind == "files") && !c.ended {
		select {
		case c.allClosed <- struct{}{}:
		default:
		}
	}
}

// newRecordingID is a fresh UUIDv7 (RFC 9562 5.7): 48-bit Unix milliseconds,
// version 7, 74 random bits, variant 10.
func newRecordingID() [16]byte {
	var id [16]byte
	_, _ = rand.Read(id[6:]) // crypto/rand.Read never returns an error
	ms := uint64(time.Now().UnixMilli())
	id[0], id[1], id[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
	id[3], id[4], id[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	id[6] = id[6]&0x0f | 0x70
	id[8] = id[8]&0x3f | 0x80
	return id
}

// uuidText is id in canonical lowercase UUID form.
func uuidText(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
