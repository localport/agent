// Package session serves remote access sessions on a device. Each session
// stream from the device's session mux carries one SSH connection: Server
// runs an x/crypto/ssh server on it with the device key as host key, admits
// the client by its SSH user certificate (signed by a session CA key, for the
// serial the edge admitted, for this device, for a login the local config
// enables), and serves the channels the certificate's kind allows: session
// channels through the root session launcher (a terminal on a PTY, a command
// (exec) or the SFTP subsystem), local and remote port forwarding, and VNC or
// RDP desktop channels relayed to the configured local target through a
// protocol filter. When the certificate asks for recording, each session
// channel opens its own recording and the connection's port forwards share
// one forwards recording; a desktop connection is never recorded.
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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
	"github.com/localport/agent/internal/recording"
)

// Reasons a connection ends with, written to its open channels' stderr and recorded.
const (
	CloseIdle     = "idle"
	CloseShutdown = "shutdown"
	// CloseConfigChanged ends the sessions of a device whose local config
	// entry a reload changed or removed.
	CloseConfigChanged = "config_changed"
	// CloseExited: the last channel of a terminal or files connection, or a
	// desktop connection's channel, closed.
	CloseExited = "exited"
)

const (
	maxSessions = 8
	// maxHandshakes bounds the streams between Serve's start and their
	// handshake decision: the edge carries at most 16 session streams per
	// mux, and one mux at a time serves a device.
	maxHandshakes = 16
	// maxChannels bounds the session channels of one connection; a terminal
	// connection has one.
	maxChannels       = 4
	keyRefreshTimeout = 3 * time.Second
	// serverVersion is the SSH identification string.
	serverVersion = "SSH-2.0-localport"
)

// Handshake and end bounds, variables so tests shorten them.
var (
	// handshakeTimeout bounds key exchange and userauth from the stream's start.
	handshakeTimeout = 10 * time.Second
	// interactiveAuthTimeout bounds one keyboard-interactive prompt, which a
	// person answers, as the trust dialog does; the rest of the handshake
	// stays under handshakeTimeout.
	interactiveAuthTimeout = 5 * time.Minute
	// endWriteTimeout bounds the end reason writes of a connection that is
	// ending; the connection closes after it whether or not they completed.
	endWriteTimeout = 2 * time.Second
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
	// permFilesDownload and permFilesUpload are present when the
	// certificate's files@localport.io option permits that SFTP direction.
	permFilesDownload = "files-download"
	permFilesUpload   = "files-upload"
	// permClipboardCopy and permClipboardPaste are present when the
	// certificate's clipboard@localport.io option permits that direction.
	permClipboardCopy  = "clipboard-copy"
	permClipboardPaste = "clipboard-paste"
	// permIdle is the certificate's idle@localport.io timeout, in its wire form.
	permIdle = "idle"
)

// ServerConfig is one device's session server configuration. Capabilities,
// Logins and Desktop come only from the device's local config.
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
	// VNCTarget is the configured vnc target, HOST:PORT: the only address a
	// vnc connection's channel reaches, whatever it requests.
	VNCTarget string
	// RDPTarget is the configured rdp target, HOST:PORT: the only address an
	// rdp connection's channel reaches, whatever its RDCleanPath request names.
	RDPTarget string
	// DesktopKeys holds the desktop targets' pinned server keys; nil ends
	// every connection whose handshake needs it (desktop_key_unavailable).
	DesktopKeys DesktopKeys
	// OnEvent receives one line per notable failure and one per desktop
	// connection's end. Optional.
	OnEvent func(string)
	// OnClipboard receives each clipboard transfer decision of a desktop
	// connection; it must not block. Nil reports none.
	OnClipboard func(ClipboardDecision)
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
	// OnFullDiskAccess receives the launcher's Full Disk Access reading of
	// every session start, started or refused (macOS; never empty); it must
	// not block. Nil drops them.
	OnFullDiskAccess func(reading string)

	// clock replaces the wall clock for validity, idle and desktop client
	// wait checks. Tests set it.
	clock clock
	// dialDesktop replaces the desktop target dial. Tests set it.
	dialDesktop func(ctx context.Context, network, addr string) (net.Conn, error)
	// desktopCheckTimeout replaces the desktop handshake's per-operation
	// target deadline when set. Tests set it.
	desktopCheckTimeout time.Duration
}

// clock is the time source of the validity, idle and desktop client wait
// checks. NewTimer returns the timer's channel and a stop function, which
// reports false when the timer already fired; NewDetachTimer is the same for
// a detached connection's expiry, apart so tests can fire that one alone.
type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) (<-chan time.Time, func() bool)
	NewDetachTimer(d time.Duration) (<-chan time.Time, func() bool)
}

type wallClock struct{}

func (c wallClock) NewDetachTimer(d time.Duration) (<-chan time.Time, func() bool) {
	return c.NewTimer(d)
}

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
	mu      sync.Mutex
	closing int // Shutdown calls in progress
	// refreshes cancels the key refreshes in flight (keyRefreshContext).
	refreshes map[*context.CancelFunc]struct{}
	sessions  int // slots taken, at most maxSessions
	// handshakes counts the Serve calls before their handshake decision, at
	// most maxHandshakes; capLogged is when a stream over it was last logged.
	handshakes int
	capLogged  time.Time
	// forwards counts every connection's forward channels, at most maxDeviceForwards.
	forwards int
	handlers map[*handler]struct{}
	// conns holds every live resumable connection by its resume handle.
	conns map[string]*resumable
	// ended holds the end records of connections that ended detached, by resume handle.
	ended map[string]*endRecord
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
	// counted is true while a Serve call holds one of Server.handshakes;
	// guarded by mu.
	counted bool
}

// resumable is one connection's resume state. The fields after ended are
// guarded by Server.mu.
type resumable struct {
	rc     *ResumableConn
	handle string
	resumeBinding
	// ended delivers an end decided outside run: detach timeout, a resume
	// refused or lost.
	ended chan string

	// running counts the Serve calls working on the connection: a first
	// connect's stream and each resume from its claim to its end. The detach
	// timer runs only while it is zero.
	running int
	// resuming is one resume's claim, held from beginResume until its stream
	// is installed or it failed: positions are in the signed prelude, so a
	// second resume meanwhile answers resume_busy.
	resuming bool
	failures int
	expired  bool
	removed  bool
	// endDecided is set once the connection's end is decided (run's end, a
	// record, an end its resume stream answered, the proof failure limit);
	// no later expiry leaves an end record for it.
	endDecided bool
	// stopTimer stops the armed detach timer; timer names it, so a fire that
	// raced a stop or a re-arm is ignored.
	stopTimer func()
	// deadline is when a detached connection ends detach_timeout: set when
	// its last stream handler ended, cleared only by an installed stream.
	deadline time.Time
	timer    *struct{}
	// conn is the connection run serves; set by run.
	conn *conn
	// admitted is the last installed resume's admission, set before its
	// stream is installed; run starts under it when a resume came first.
	admitted *connAdmission
}

// resumeBinding is what a resume of a connection must match before its
// proof, and the token the proof is checked with.
type resumeBinding struct {
	token   []byte
	subject string
	kind    string
	// login is the first connect's principal, the SSH user; every resume
	// certificate must name it.
	login string
	// certKey is the certificate key the first connect bound the connection
	// to; userauth and every resume must present it.
	certKey []byte
	// serial is the serial of the certificate that admitted the first connect.
	serial uint64
}

// endRecord keeps the end reason of a connection that ended detached. A
// resume of its handle passes the live-handle checks and, once its proof
// verifies, is answered statusEnded with the reason. Guarded by Server.mu;
// holds no slot or goroutine; lives detachTimeout; at most maxSessions.
type endRecord struct {
	resumeBinding
	// received is the connection's received position at the end, signed into
	// the resume reply as a live handle's is.
	received uint64
	reason   string
	expires  time.Time
	// resuming and failures are a live handle's claim and proof failures.
	resuming bool
	failures int
}

// endRecordable reports whether an end leaves a record. A client's close and
// the reasons a resume stream already answered leave none.
func endRecordable(reason string) bool {
	switch reason {
	case "", CloseResumeRefused, CloseResumeLost, CloseRecordingRequired:
		return false
	}
	return true
}

// recordEndLocked leaves e's end record for reason, unless the reason leaves
// none or e already has one. Expired records go first; at maxSessions the
// oldest is evicted.
func (s *Server) recordEndLocked(e *resumable, reason string) {
	if e.endDecided || !endRecordable(reason) {
		return
	}
	e.endDecided = true
	if _, ok := s.ended[e.handle]; ok {
		return
	}
	now := s.cfg.clock.Now()
	var oldest string
	for handle, r := range s.ended {
		if !now.Before(r.expires) {
			delete(s.ended, handle)
		} else if oldest == "" || r.expires.Before(s.ended[oldest].expires) {
			oldest = handle
		}
	}
	if len(s.ended) >= maxSessions {
		delete(s.ended, oldest)
	}
	s.ended[e.handle] = &endRecord{resumeBinding: e.resumeBinding, received: e.rc.Received(),
		reason: reason, expires: now.Add(detachTimeout)}
}

// recordLocked returns handle's end record, deleting it when it expired.
func (s *Server) recordLocked(handle string) *endRecord {
	r := s.ended[handle]
	if r != nil && !s.cfg.clock.Now().Before(r.expires) {
		delete(s.ended, handle)
		return nil
	}
	return r
}

// dropRecordLocked deletes r unless another record took its handle.
func (s *Server) dropRecordLocked(handle string, r *endRecord) {
	if s.ended[handle] == r {
		delete(s.ended, handle)
	}
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

// afterAttemptClaimCleared is a test hook run in endAttempt's critical section,
// after the claim is cleared and before the hold is released.
var afterAttemptClaimCleared atomic.Pointer[func()]

// afterResumeProof, when set by a test, runs in serveResume once the proof
// verified, before the close, lost and install branches.
var afterResumeProof atomic.Pointer[func(*resumable)]

// afterResumeReadmit, when set by a test, runs in serveResume after readmit
// and before the stream is installed.
var afterResumeReadmit atomic.Pointer[func(*resumable)]

// afterResumeInstall, when set by a test, runs in serveResume once the
// stream is installed and before the resume's claim is released.
var afterResumeInstall atomic.Pointer[func(*resumable)]

// afterConnPublished, when set by a test, runs in serveNew once addConn has
// published the connection and before its stream runs.
var afterConnPublished atomic.Pointer[func(*resumable)]

// onConnEnd, when set by a test, gets the reason serveConn ends a connection
// with ("" for a client's close), before its channels end.
var onConnEnd atomic.Pointer[func(reason string)]

// beforeRunDecidesEnd, when set by a test, runs in run once its end reason is
// known and before decideEnd.
var beforeRunDecidesEnd atomic.Pointer[func(*Server, *resumable)]

// afterIdleCheck, when set by a test, gets each idle decision run makes:
// timer is true for the idle timer and false for a readmit signal, decided
// true when it ends the connection idle.
var afterIdleCheck atomic.Pointer[func(s *Server, timer, decided bool)]

func idleChecked(s *Server, timer, decided bool) {
	if hook := afterIdleCheck.Load(); hook != nil {
		(*hook)(s, timer, decided)
	}
}

// beforeConnUnregister, when set by a test, runs in removeConn just before
// the connection's handler is unregistered, the step that lets Shutdown
// return. It gets the server, since every test's servers share it.
var beforeConnUnregister atomic.Pointer[func(*Server)]

// detachTimeout bounds how long a connection waits detached for a resume.
const detachTimeout = 5 * time.Minute

// closeFlushTimeout bounds how long an ended connection's last bytes and
// closeTag may take on its attached stream; a variable for tests.
var closeFlushTimeout = 5 * time.Second

// NewServer returns the session server of one device.
func NewServer(cfg ServerConfig) *Server {
	if cfg.clock == nil {
		cfg.clock = wallClock{}
	}
	return &Server{cfg: cfg, launcher: launcherFor(cfg.Launcher), handlers: map[*handler]struct{}{},
		conns: map[string]*resumable{}, ended: map[string]*endRecord{}}
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

// noteFullDiskAccess passes a session start's launcher reading on; an empty
// one (off macOS, or a refusal before the reading) is dropped.
func (s *Server) noteFullDiskAccess(reading string) {
	if reading != "" && s.cfg.OnFullDiskAccess != nil {
		s.cfg.OnFullDiskAccess(reading)
	}
}

// Serve runs one session stream to its end: a first connect starts an SSH
// connection on a ResumableConn; a resume attaches the stream to a detached
// one. id is the edge's session id for the stream (a first connect's
// recordings use it), serial the certificate serial the edge admitted,
// clientAddr the client's `ip:port` from the notice (empty when unknown). The
// connection outlives the stream while it waits detached for a resume; the
// caller closes stream after Serve returns. With maxHandshakes streams awaiting
// their handshake decision, Serve returns at once unread: refusedUnread.
func (s *Server) Serve(stream net.Conn, id [16]byte, serial uint64, clientAddr string) (refusedUnread bool) {
	h := &handler{stop: make(chan struct{}), handshaking: true, abort: func() { _ = stream.SetDeadline(time.Now()) }}
	if ok, logIt := s.register(h); !ok {
		if logIt {
			s.log("session: %d handshakes in progress, closing new streams", maxHandshakes)
		}
		return true
	}
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
		return false
	}
	if hello != nil {
		s.serveNew(h, stream, hello, id, serial, clientAddr)
		return false
	}
	s.serveResume(h, stream, resume, id, serial, clientAddr)
	return false
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
func (s *Server) serveNew(h *handler, stream net.Conn, hello *helloMsg, id [16]byte, serial uint64, clientAddr string) {
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
	// Before admit, whose CA refresh a forged hello must not trigger.
	if !verifyPrelude(cert.Key, clientSigContext, transcript(hello.noSig()), hello.Sig) {
		refuse("the hello signature does not verify with the certificate's key")
		return
	}
	adm, err := s.admit(cert, cert.ValidPrincipals[0], device, serial)
	if err != nil {
		refuse("%v", err)
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

	e := &resumable{rc: NewResumableConn(), handle: string(handle), ended: make(chan string, 1),
		resumeBinding: resumeBinding{token: token, subject: adm.Subject, kind: adm.Kind,
			login: adm.Login, certKey: cert.Key.Marshal(), serial: serial}}
	ch := &handler{stop: make(chan struct{}), handshaking: true, abort: func() { e.rc.End(errConnEnded) }}
	// Installed before addConn publishes e, so a resume of the new handle
	// always finds this stream attached and takes over from it. A fresh conn
	// accepts position 0.
	run, _ := e.rc.Install(stream, 0)
	if !s.addConn(e, ch) {
		return
	}
	if hook := afterConnPublished.Load(); hook != nil {
		(*hook)(e)
	}
	started = true
	go s.serveConn(ch, e, id, serial, cert, clientAddr)
	defer s.release(e)
	s.runStream(e, run)
}

// serveResume runs a resume: the handle's connection, a resume certificate
// for its original serial, subject and key signed by that key, a fresh
// host-key-signed reply, then the token proof, before any byte is resent.
func (s *Server) serveResume(h *handler, stream net.Conn, m *resumeMsg, id [16]byte, serial uint64, clientAddr string) {
	refuse := func(status uint32, format string, args ...any) {
		s.log("session: resume refused: "+format, args...)
		_ = writePrelude(stream, resumeReplyMsg{Status: status})
	}
	host, device, err := s.hostIdentity()
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	// The signature is checked before the claim and the CA refresh, so a
	// forged resume neither blocks a real one nor triggers a refresh.
	cert, err := parsePreludeCert(m.Cert)
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	if !verifyPrelude(cert.Key, clientSigContext, transcript(m.noSig()), m.Sig) {
		refuse(statusRefused, "the resume signature does not verify with the certificate's key")
		return
	}
	handle := string(m.Handle)
	e, rec, status := s.beginResume(h, handle)
	if status != statusOK {
		refuse(status, "the connection is gone, resuming or shutting down")
		return
	}
	// The hold, and a record's claim, end with this call. A connection's claim
	// ends at the install (unclaim) or, for a failed resume, with the hold in one
	// critical section (endAttempt), so no other resume holds in between and the
	// detach deadline is checked after every attempt.
	claimed := true
	bound := rec
	if rec == nil {
		bound = &endRecord{resumeBinding: e.resumeBinding}
		defer func() { s.endAttempt(e, claimed) }()
	} else {
		defer s.endRecordAttempt(rec)
	}
	adm, err := s.withCARefresh(cert, func() (*admission, error) {
		return verifyResumeCert(cert, s.caKeys(), device, serial, bound.serial, s.cfg.clock.Now())
	})
	switch {
	case err != nil:
		refuse(statusRefused, "%v", err)
		return
	case adm.Subject != bound.subject || adm.Kind != bound.kind || adm.Login != bound.login || !bytes.Equal(cert.Key.Marshal(), bound.certKey):
		refuse(statusRefused, "the resume certificate is for another subject, kind, login or key")
		return
	}
	// The connection runs under this admission once installed, so it meets
	// the local config as a first connect's does.
	if err := s.localRefusal(adm); err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	// A resume for a live stream detaches it first, which settles positions.
	// A position outside the buffer ends the connection only once the proof
	// shows the client sent it, not on a replayed message. A record signs the
	// position the connection ended with.
	lost, received := false, bound.received
	if e != nil {
		e.rc.Detach()
		lost, received = !e.rc.CanResumeFrom(m.Position), e.rc.Received()
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		refuse(statusRefused, "%v", err)
		return
	}
	reply := resumeReplyMsg{Status: statusOK, AgentKey: priv.PublicKey().Bytes(), Position: received}
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
	if !hmac.Equal(proof.Proof, resumeProof(bound.token, th)) {
		s.log("session: resume refused: the token proof does not verify")
		_ = writePrelude(stream, proofReplyMsg{Status: statusRefused})
		if rec != nil {
			s.recordProofFailed(handle, rec)
		} else if s.proofFailed(e) {
			e.endWith(CloseResumeRefused)
		}
		return
	}
	if hook := afterResumeProof.Load(); hook != nil {
		(*hook)(e)
	}
	if rec == nil {
		// The connection may have ended detached during this attempt (its
		// idle timer runs until readmit): its record answers the resume.
		s.mu.Lock()
		rec = s.recordLocked(handle)
		s.mu.Unlock()
	}
	if rec != nil {
		s.answerRecord(stream, handle, rec, m.Close)
		return
	}
	if m.Close {
		// A close resume ends the connection as a received closeTag does; a
		// lost position does not matter to an end. The conn takes no later
		// stream, so the token is spent.
		s.log("session: resume closed the connection")
		_ = writePrelude(stream, proofReplyMsg{Status: statusOK})
		s.decideAnsweredEnd(e)
		// Queued before the release can expire e, so run ends with the
		// client's close ("") and not detach_timeout.
		e.endWith("")
		e.rc.CloseRemote()
		return
	}
	if lost {
		s.log("session: resume refused: position %d is outside the send buffer", m.Position)
		_ = writePrelude(stream, proofReplyMsg{Status: statusLost})
		s.endAnswered(e, CloseResumeLost)
		e.rc.End(ErrResumeLost)
		return
	}
	if !s.endHandshake(h) {
		return
	}
	// The connection continues under the resume certificate and this stream's
	// session id, which the edge attests for recordings, before any byte of
	// the stream is read.
	// From readmit to settleResume run decides no idle end, so a resume past the
	// idle timeout ends `idle` over its installed stream, not as a lost install.
	violated := s.readmit(e, &connAdmission{admission: adm, sessionID: uuidText(id), clientAddr: clientAddr})
	settled := false
	defer func() {
		if !settled {
			s.settleResume(e)
		}
	}()
	if violated {
		s.log("session: resume refused: %s: the resume names a recording that a running channel or forwards helper does not have", CloseRecordingRequired)
		_ = writePrelude(stream, proofReplyMsg{Status: statusLost})
		s.endAnswered(e, CloseRecordingRequired)
		e.rc.End(ErrResumeLost)
		return
	}
	if hook := afterResumeReadmit.Load(); hook != nil {
		(*hook)(e)
	}
	// A connection that ended detached during this attempt left a record,
	// answered as any verified resume of it; Install would close the stream.
	s.mu.Lock()
	r := s.recordLocked(handle)
	s.mu.Unlock()
	if r != nil {
		s.answerRecord(stream, handle, r, false)
		return
	}
	_ = stream.SetDeadline(time.Time{})
	// Installed while this resume still holds its claim, so no other resume
	// runs between the positions it signed and the stream taking over. An
	// expired or removed connection's conn has ended and refuses the stream.
	run, _ := e.rc.Install(stream, m.Position)
	if run == nil {
		_ = writePrelude(stream, proofReplyMsg{Status: statusLost})
		return
	}
	// The connection is attached again: its detach deadline is gone, and the
	// next lost stream starts a full one (release).
	s.mu.Lock()
	e.deadline = time.Time{}
	s.mu.Unlock()
	if hook := afterResumeInstall.Load(); hook != nil {
		(*hook)(e)
	}
	// A failed write ends the stream at once; run still runs it, so its end
	// detaches the connection as any lost stream.
	_ = writePrelude(stream, proofReplyMsg{Status: statusOK})
	s.settleResume(e)
	settled = true
	s.unclaim(e)
	claimed = false
	s.mark(e, markerAttach)
	s.runStream(e, run)
}

// readmit records a verified resume's admission on e and applies it to the
// connection run serves, if it started. It reports that the admission names a
// recording the running connection cannot meet; the caller then ends it.
func (s *Server) readmit(e *resumable, a *connAdmission) bool {
	s.mu.Lock()
	e.admitted = a
	c := e.conn
	s.mu.Unlock()
	return c != nil && c.readmit(a)
}

// settleResume ends the idle hold readmit put on e's connection: run decides
// the idle timeout again, now against an installed stream or, for a resume
// that failed after readmit, as for any detached connection.
func (s *Server) settleResume(e *resumable) {
	s.mu.Lock()
	c := e.conn
	s.mu.Unlock()
	if c != nil {
		c.settleResume()
	}
}

// answerRecord answers a verified resume of an end record and deletes it: a
// close resume is answered statusOK, any other statusEnded with the reason.
func (s *Server) answerRecord(stream net.Conn, handle string, r *endRecord, closeConn bool) {
	s.mu.Lock()
	s.dropRecordLocked(handle, r)
	s.mu.Unlock()
	if closeConn {
		s.log("session: resume closed an ended connection")
		_ = writePrelude(stream, proofReplyMsg{Status: statusOK})
		return
	}
	s.log("session: resume answered: the connection ended %s", r.reason)
	_ = writePrelude(stream, proofReplyMsg{Status: statusEnded, Reason: r.reason})
}

// endRecordAttempt ends a resume attempt's claim on an end record.
func (s *Server) endRecordAttempt(r *endRecord) {
	s.mu.Lock()
	r.resuming = false
	s.mu.Unlock()
}

// recordProofFailed counts a failed proof against an end record; at
// maxProofFailures the record is deleted.
func (s *Server) recordProofFailed(handle string, r *endRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r.failures++
	if r.failures >= maxProofFailures {
		s.dropRecordLocked(handle, r)
	}
}

// mark queues label on every recording of e's connection, if run started.
func (s *Server) mark(e *resumable, label string) {
	s.mu.Lock()
	c := e.conn
	s.mu.Unlock()
	if c != nil {
		c.markRecordings(label)
	}
}

// runStream runs an installed stream; a stream lost without a closeTag marks
// every recording `detach`. The detach timer is release's.
func (s *Server) runStream(e *resumable, run func() AttachEnd) {
	if run() == Detached {
		s.mark(e, markerDetach)
	}
}

// release ends one Serve call's work on e. The last one, unless e is gone,
// fixes the detach deadline if none is set (the connection's stream just
// ended) and arms the timer for the time left; with none left it expires e
// at once. The deadline is absolute: a resume attempt pauses the expiry while
// it runs but never moves the deadline, which only an installed stream clears
// (the handle is not secret, so an attempt must not buy time).
func (s *Server) release(e *resumable) {
	s.mu.Lock()
	expire := s.releaseLocked(e)
	s.mu.Unlock()
	if expire {
		e.expire()
	}
}

// endAttempt ends a resume attempt: its claim, when it still holds one (a
// failed resume), and its hold, in one critical section with the deadline
// check (releaseLocked).
func (s *Server) endAttempt(e *resumable, claimed bool) {
	s.mu.Lock()
	if claimed {
		e.resuming = false
	}
	if hook := afterAttemptClaimCleared.Load(); hook != nil {
		(*hook)()
	}
	expire := s.releaseLocked(e)
	s.mu.Unlock()
	if expire {
		e.expire()
	}
}

// releaseLocked is release under s.mu; true means e expired and the caller
// calls e.expire once s.mu is released.
func (s *Server) releaseLocked(e *resumable) bool {
	e.running--
	if e.running > 0 || e.removed || e.expired {
		return false
	}
	now := s.cfg.clock.Now()
	if e.deadline.IsZero() {
		e.deadline = now.Add(detachTimeout)
	}
	left := e.deadline.Sub(now)
	if left <= 0 {
		s.expireLocked(e)
		return true
	}
	fire, stop := s.cfg.clock.NewDetachTimer(left)
	cancel := make(chan struct{})
	timer := &struct{}{}
	e.timer = timer
	e.stopTimer = func() {
		stop()
		close(cancel)
	}
	go func() {
		select {
		case <-fire:
			s.mu.Lock()
			expire := e.timer == timer && e.running == 0 && !e.removed && !e.expired
			if expire {
				s.expireLocked(e)
				e.stopTimer, e.timer = nil, nil
			}
			s.mu.Unlock()
			if expire {
				e.expire()
			}
		case <-cancel:
		}
	}()
	return false
}

// holdLocked starts one Serve call's work on e: the detach timer stops.
func (e *resumable) holdLocked() {
	e.running++
	e.stopTimerLocked()
}

func (e *resumable) stopTimerLocked() {
	if e.stopTimer != nil {
		e.stopTimer()
		e.stopTimer, e.timer = nil, nil
	}
}

// addConn registers a started connection and its handler unless Shutdown is
// running; the first connect's stream holds it (release).
func (s *Server) addConn(e *resumable, h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing > 0 {
		return false
	}
	s.handlers[h] = struct{}{}
	s.conns[e.handle] = e
	e.holdLocked()
	return true
}

// beginResume claims handle's connection, or its end record, for one resume:
// statusLost when neither exists, statusBusy while another resume holds the
// claim, statusRefused during Shutdown, in that order for both. A connection's
// claim also holds it (release). A claim ends h's handshake count.
func (s *Server) beginResume(h *handler, handle string) (*resumable, *endRecord, uint32) {
	s.mu.Lock()
	e := s.conns[handle]
	expired := e != nil && !e.removed && !e.expired && e.running == 0 && !e.deadline.IsZero() &&
		!s.cfg.clock.Now().Before(e.deadline)
	if expired {
		// Past its deadline and the timer has not fired yet: expired here,
		// so no resume can claim a connection that is over.
		s.expireLocked(e)
		e.stopTimerLocked()
	}
	claimed, rec, status := s.claimLocked(h, handle, e)
	s.mu.Unlock()
	if expired {
		e.expire()
	}
	return claimed, rec, status
}

// claimLocked is beginResume's claim under s.mu; e is handle's connection.
func (s *Server) claimLocked(h *handler, handle string, e *resumable) (*resumable, *endRecord, uint32) {
	// A record exists only for an ended connection, so it is checked first:
	// its connection may still be in s.conns while run ends.
	if r := s.recordLocked(handle); r != nil {
		switch {
		case s.closing > 0:
			return nil, nil, statusRefused
		case r.resuming:
			return nil, nil, statusBusy
		}
		r.resuming = true
		s.endCountLocked(h)
		return nil, r, statusOK
	}
	switch {
	case e == nil || e.removed || e.expired:
		return nil, nil, statusLost
	case s.closing > 0:
		return nil, nil, statusRefused
	case e.resuming:
		return nil, nil, statusBusy
	}
	e.resuming = true
	e.holdLocked()
	s.endCountLocked(h)
	return e, nil, statusOK
}

// unclaim releases a resume's claim once its stream is installed; a failed
// resume's claim ends with its hold in endAttempt.
func (s *Server) unclaim(e *resumable) {
	s.mu.Lock()
	e.resuming = false
	s.mu.Unlock()
}

// decideEnd decides run's end of e for reason and reports whether e was
// detached. A detached end leaves the record a later resume is answered
// with; once decided, no later expiry records one.
func (s *Server) decideEnd(e *resumable, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	detached := !e.rc.Attached()
	if detached {
		s.recordEndLocked(e, reason)
	}
	e.endDecided = true
	return detached
}

// expireLocked marks a detached connection expired and leaves its
// detach_timeout end record in the same critical section, so no resume finds
// it expired without one; the caller runs e.expire after releasing s.mu.
func (s *Server) expireLocked(e *resumable) {
	e.expired = true
	s.recordEndLocked(e, CloseDetachTimeout)
}

// expire ends a detached connection detach_timeout and drops its conn, so
// run's end, or a write blocked on the conn, returns.
func (e *resumable) expire() {
	e.endWith(CloseDetachTimeout)
	e.rc.End(errConnEnded)
}

// proofFailed counts a failed proof against e and reports whether it reached
// maxProofFailures. At the limit e's end is decided in the same critical
// section: resume_refused leaves no record, and neither does a later expiry.
func (s *Server) proofFailed(e *resumable) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.failures++
	if e.failures < maxProofFailures {
		return false
	}
	e.endDecided = true
	return true
}

// endAnswered ends e for a reason its resume stream already answered
// (resume_lost, recording_required).
func (s *Server) endAnswered(e *resumable, reason string) {
	s.decideAnsweredEnd(e)
	e.endWith(reason)
}

// decideAnsweredEnd decides an end the resume stream answered before the
// attempt releases e, so an expiry the release reaches leaves no record.
func (s *Server) decideAnsweredEnd(e *resumable) {
	s.mu.Lock()
	e.endDecided = true
	s.mu.Unlock()
}

// serveConn runs one connection: the SSH handshake on its ResumableConn,
// bounded by handshakeTimeout, then run. It owns the session slot serveNew
// took and removes the connection, slot included, when it ends.
func (s *Server) serveConn(h *handler, e *resumable, id [16]byte, serial uint64, admitted *ssh.Certificate, clientAddr string) {
	// stoppedBy is Shutdown's reason when it ended the handshake, decided where
	// the handshake ends so removeConn never reads a later Shutdown's.
	var stoppedBy string
	defer func() { s.removeConn(e, h, stoppedBy) }()
	defer func() {
		if r := recover(); r != nil {
			s.log("session: connection panic: %v", r)
		}
	}()
	handshake := time.AfterFunc(handshakeTimeout, func() { e.rc.End(errHandshakeTimeout) })
	secret := &connSecret{}
	defer secret.clear()
	cfg, err := s.serverConfig(serial, secret, admitted, func(d time.Duration) { handshake.Reset(d) })
	if err != nil {
		handshake.Stop()
		s.log("session: %v", err)
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(e.rc, cfg)
	handshake.Stop()
	ended := !s.endHandshake(h)
	if ended {
		// h.stop is closed, so stopReason is final and read without s.mu.
		stoppedBy = h.stopReason
	}
	if ended || err != nil {
		if err != nil {
			s.log("session: SSH handshake or userauth failed: %v", err)
		}
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	defer conn.Close()
	s.run(h, conn, chans, reqs, &connAdmission{admission: admissionOf(conn.Permissions), sessionID: uuidText(id), clientAddr: clientAddr}, secret.password, e)
}

// removeConn forgets an ended connection, gives an attached stream
// closeFlushTimeout to flush, then frees its session slot. The slot is freed
// before the handler is unregistered so a returned Shutdown leaves no slot
// taken. stoppedBy, the reason of a Shutdown that ended the SSH handshake,
// leaves an end record whether attached or not: Shutdown's abort does not
// tell the client. Other ends before run leave none.
func (s *Server) removeConn(e *resumable, h *handler, stoppedBy string) {
	s.mu.Lock()
	if stoppedBy != "" {
		s.recordEndLocked(e, stoppedBy)
	}
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
	s.releaseSlot()
	if hook := beforeConnUnregister.Load(); hook != nil {
		(*hook)(s)
	}
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
// keep no state across connections. Userauth proves possession of the key of
// admitted, the certificate the edge and the prelude admitted: the client may
// present that key plain or in any certificate over it (OpenSSH presents the
// certificate file it loaded before ssh-proxy started, which may predate a
// certificate the proxy minted after a refusal). The identity is built from
// admitted alone, verified again for the user at VerifiedPublicKeyCallback,
// and returned as the connection's Permissions; nothing in the presented
// certificate is trusted. For a password login that step is a partial
// success whose only next method is one keyboard-interactive prompt, so the
// prompt exists only after the key is proven; its answer goes to secret.
func (s *Server) serverConfig(serial uint64, secret *connSecret, admitted *ssh.Certificate, rearmHandshake func(time.Duration)) (*ssh.ServerConfig, error) {
	hostKey, device, err := s.hostIdentity()
	if err != nil {
		return nil, err
	}
	bound := admitted.Key.Marshal()
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM},
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
		},
		ServerVersion: serverVersion,
		MaxAuthTries:  3,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if cert, ok := key.(*ssh.Certificate); ok {
				key = cert.Key
			}
			if !bytes.Equal(key.Marshal(), bound) {
				return nil, refuseCert("a key other than the prelude's")
			}
			return &ssh.Permissions{}, nil
		},
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, _ ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			adm, err := s.admit(admitted, meta.User(), device, serial)
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
					rearmHandshake(interactiveAuthTimeout)
					answers, err := client("", "", []string{passwordPrompt}, []bool{false})
					rearmHandshake(handshakeTimeout)
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
	if err := s.localRefusal(adm); err != nil {
		return nil, err
	}
	return adm, nil
}

// localRefusal applies the local config to a verified admission, fresh or
// resume: the kind enabled and served by this build, the login enabled, and
// a recording key that matches (refreshing the keys once on a mismatch).
func (s *Server) localRefusal(adm *admission) error {
	switch {
	case !s.kindEnabled(adm.Kind):
		return refuseCert("kind %q is not enabled on this device", adm.Kind)
	case isDesktopKind(adm.Kind):
		// The agent process dials the target: no login or launcher applies.
		switch {
		case adm.Login != desktopPrincipal:
			return refuseCert("a desktop certificate names login %q", desktopPrincipal)
		case adm.Rec != nil:
			return refuseCert("a desktop session is never recorded")
		}
		return nil
	case adm.Kind != "terminal" && adm.Kind != "ssh" && adm.Kind != "files":
		return refuseCert("kind %q is not served by this agent", adm.Kind)
	case s.launcher == nil:
		return refuseCert("this build serves no session")
	case !slices.Contains(s.cfg.Logins, adm.Login):
		return refuseCert("login %q is not enabled on this device", adm.Login)
	case adm.Rec != nil && !s.recordingKeyMatches(adm.Rec.PubSHA256):
		return refuseCert("the recording key is not the held team key")
	}
	return nil
}

// withCARefresh runs verify, and once more after a CA key refresh when it
// failed for a certificate signed by no held CA key.
func (s *Server) withCARefresh(cert *ssh.Certificate, verify func() (*admission, error)) (*admission, error) {
	adm, err := verify()
	if err != nil && s.cfg.RefreshKeys != nil && !signedByCA(cert, s.caKeys()) {
		ctx, cancel := s.keyRefreshContext()
		if rerr := s.cfg.RefreshKeys(ctx); rerr != nil {
			s.log("session: CA key refresh for an unknown CA key: %v", rerr)
		}
		cancel()
		adm, err = verify()
	}
	return adm, err
}

// keyRefreshContext bounds a key refresh by keyRefreshTimeout and ends it when
// Shutdown starts, so no refresh outlasts Shutdown's budget.
func (s *Server) keyRefreshContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), keyRefreshTimeout)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing > 0 {
		cancel()
		return ctx, cancel
	}
	if s.refreshes == nil {
		s.refreshes = make(map[*context.CancelFunc]struct{})
	}
	s.refreshes[&cancel] = struct{}{}
	return ctx, func() {
		s.mu.Lock()
		delete(s.refreshes, &cancel)
		s.mu.Unlock()
		cancel()
	}
}

func (s *Server) caKeys() []ed25519.PublicKey {
	if s.cfg.CAKeys == nil {
		return nil
	}
	return s.cfg.CAKeys()
}

// permissions carries a into the connection's Permissions.
func (a *admission) permissions() *ssh.Permissions {
	ext := map[string]string{permKind: a.Kind, permSubject: a.Subject, permCert: base64.RawURLEncoding.EncodeToString(a.Cert),
		permIdle: strconv.FormatInt(int64(a.Idle/time.Second), 10)}
	if a.Rec != nil {
		ext[permRecPol], ext[permRecPub] = a.Rec.Policy, a.Rec.PubSHA256
	}
	if a.ForwardLocal {
		ext[permFwdLocal] = ""
	}
	if a.ForwardRemote {
		ext[permFwdRemote] = ""
	}
	if a.Files.Download {
		ext[permFilesDownload] = ""
	}
	if a.Files.Upload {
		ext[permFilesUpload] = ""
	}
	if a.Clipboard.Copy {
		ext[permClipboardCopy] = ""
	}
	if a.Clipboard.Paste {
		ext[permClipboardPaste] = ""
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
	_, a.Files.Download = ext[permFilesDownload]
	_, a.Files.Upload = ext[permFilesUpload]
	_, a.Clipboard.Copy = ext[permClipboardCopy]
	_, a.Clipboard.Paste = ext[permClipboardPaste]
	// permissions wrote a value checkCert accepted. A value that does not
	// parse leaves Idle zero, which ends the connection at its first idle check.
	a.Idle, _ = parseIdle(ext[permIdle])
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
	ctx, cancel := s.keyRefreshContext()
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

// logMessages logs the PAM messages of a session setup for login, quoted.
func (s *Server) logMessages(login string, msgs []string) {
	for _, m := range msgs {
		s.log("session: PAM message for %q: %q", login, m)
	}
}

// register adds a Serve call's handler and counts its handshake. With
// maxHandshakes counted it refuses h; logIt is true at most once a second.
func (s *Server) register(h *handler) (ok, logIt bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handshakes >= maxHandshakes {
		now := s.cfg.clock.Now()
		if now.Sub(s.capLogged) < time.Second {
			return false, false
		}
		s.capLogged = now
		return false, true
	}
	s.handshakes++
	h.counted = true
	s.handlers[h] = struct{}{}
	return true, false
}

// endCountLocked ends h's handshake count, if it holds one, under s.mu.
func (s *Server) endCountLocked(h *handler) {
	if h.counted {
		h.counted = false
		s.handshakes--
	}
}

// unregister removes a handler; a Serve call that ends before its handshake
// decision ends its count here.
func (s *Server) unregister(h *handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endCountLocked(h)
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
// has stopped h. A slot taken ends h's handshake count.
func (s *Server) takeSlot(h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing > 0 || h.stopped || s.sessions >= maxSessions {
		return false
	}
	s.sessions++
	s.endCountLocked(h)
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
	for cancel := range s.refreshes {
		(*cancel)()
	}
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

// conn is one admitted connection's state, shared by run and its channel goroutines.
type conn struct {
	s *Server
	// adm is the connection's admission: the first connect's, replaced by each
	// installed resume's (readmit). Load it once per decision.
	adm atomic.Pointer[connAdmission]
	// readmitted receives, without blocking, after readmit stored a new
	// admission and after settleResume, so run re-reads resumePending and
	// re-arms the idle timer for the current admission's timeout.
	readmitted chan struct{}
	login      string
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
	open   int
	served int
	ended  bool
	// resumePending is true from a resume's readmit until its settleResume:
	// run decides no idle end meanwhile.
	resumePending bool
	channels      map[*channel]struct{}
	// desktop is a desktop connection's one channel once its open began.
	desktop *desktopChannel
	// allClosed receives once when a terminal or files connection's last
	// channel closed, or a desktop connection's channel ended or was refused.
	allClosed chan struct{}
}

// connAdmission is a certificate's admission with the session id of the
// stream it admitted, in UUID text form; each recording a channel opens
// names that id, which the edge attests together with the certificate.
type connAdmission struct {
	*admission
	sessionID string
	// clientAddr is the client's `ip:port` from the stream's notice, empty
	// when unknown; every launcher request of the connection carries it.
	clientAddr string
	// recordedStarts counts the recorded starts under this stream, each counted
	// before it is attempted; a resume's admission counts from zero.
	recordedStarts atomic.Int32
}

func (c *conn) active() { c.lastActivity.Store(c.s.cfg.clock.Now().UnixNano()) }

// readmit runs the connection under a resume's admission from now on and
// ends the forwards it no longer allows. Channels already open keep their
// recordings. It reports true, changing nothing else, when the admission names
// a recording that a started channel or the running forwards helper cannot
// meet; a start in progress meets the stored admission at its hand-off.
func (c *conn) readmit(a *connAdmission) bool {
	c.mu.Lock()
	c.adm.Store(a)
	c.resumePending = true
	c.signalReadmitted()
	violated := c.fwd.recordingViolatedLocked(a)
	conns, listeners, client := c.fwd.disallowedLocked()
	channels := slices.Collect(maps.Keys(c.channels))
	c.mu.Unlock()
	for _, ch := range channels {
		violated = violated || ch.recordingViolated(a)
	}
	if violated {
		return true
	}
	c.fwd.closeDisallowed(conns, listeners, client)
	// An SFTP channel's file server holds the access it started with; one the
	// new admission no longer covers ends (a channel starting now sees the new
	// admission at its hand-off instead). Its recording gets the reason as a
	// marker before the end. The end runs apart from this resume, whose stream
	// is not installed yet: the reason's stderr write waits on the send buffer.
	for _, ch := range channels {
		ch.mu.Lock()
		narrowed := !ch.stopped.Load() && ch.kind == launcher.KindSFTP && !a.Files.covers(ch.files)
		rec := ch.rec
		ch.mu.Unlock()
		if narrowed {
			if rec != nil {
				rec.marker(CloseFilesNarrowed)
			}
			go ch.end(CloseFilesNarrowed)
		}
	}
	return false
}

// settleResume ends the idle hold of the resume readmit started.
func (c *conn) settleResume() {
	c.mu.Lock()
	c.resumePending = false
	c.signalReadmitted()
	c.mu.Unlock()
}

// idleHeld reports whether a resume between readmit and settleResume holds
// the idle decision.
func (c *conn) idleHeld() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.resumePending
}

func (c *conn) signalReadmitted() {
	select {
	case c.readmitted <- struct{}{}:
	default:
	}
}

// fail ends the connection with reason unless its end is already decided.
func (c *conn) fail(reason string) {
	select {
	case c.failed <- reason:
	default:
	}
}

// run serves an admitted connection until its first recorded end: the client
// closing it, the idle timeout, a Shutdown, the last channel of a terminal or
// files connection or a desktop connection's channel closing (a failed Strict
// recording ends its own channel), or a failed Strict forwards recording, or an
// end e queues (detach timeout, a resume refused or lost). It then ends the
// forwards, writes the reason to every open channel's stderr (a detached conn
// is dropped first, so nothing waits for a stream; the writes are bounded by
// endWriteTimeout), closes the connection and joins the channels and forwards.
func (s *Server) run(h *handler, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, adm *connAdmission, password []byte, e *resumable) {
	c := &conn{s: s, login: sc.User(), password: password, readmitted: make(chan struct{}, 1),
		channels: map[*channel]struct{}{}, allClosed: make(chan struct{}, 1), failed: make(chan string, 1)}
	var wg sync.WaitGroup
	c.fwd = newForwarder(c, sc, &wg)
	s.mu.Lock()
	if e.admitted != nil {
		// A resume installed before the SSH handshake ended.
		c.adm.Store(e.admitted)
	} else {
		c.adm.Store(adm)
	}
	e.conn = c
	s.mu.Unlock()
	c.active()
	clientDone := make(chan struct{})
	wg.Go(func() {
		defer close(clientDone)
		c.accept(chans, &wg)
	})
	wg.Go(func() {
		// Global requests, answered in order: each counts as activity on every
		// kind (the browser's Stay connected is a keepalive@openssh.com); the
		// remote forwarding requests are served when allowed, every other
		// request is refused.
		for r := range reqs {
			c.active()
			ok, payload := c.fwd.globalRequest(r)
			if r.WantReply {
				_ = r.Reply(ok, payload)
			}
		}
	})

	// The idle timeout is the current admission's: a resume's certificate
	// replaces it, and readmitted re-arms the timer for the new value.
	fire, stopTimer := s.cfg.clock.NewTimer(c.adm.Load().Idle)
	idleEnded := func() bool {
		timeout := c.adm.Load().Idle
		idle := s.cfg.clock.Now().Sub(time.Unix(0, c.lastActivity.Load()))
		if idle >= timeout {
			return true
		}
		fire, stopTimer = s.cfg.clock.NewTimer(timeout - idle)
		return false
	}
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
			// A resume between readmit and settleResume holds the decision;
			// settleResume signals readmitted, which decides it.
			decided := !c.idleHeld() && idleEnded()
			idleChecked(s, true, decided)
			if decided {
				reason = CloseIdle
				break wait
			}
		case <-c.readmitted:
			stopTimer()
			decided := !c.idleHeld() && idleEnded()
			idleChecked(s, false, decided)
			if decided {
				reason = CloseIdle
				break wait
			}
		}
	}
	stopTimer()
	if hook := beforeRunDecidesEnd.Load(); hook != nil {
		(*hook)(s, e)
	}
	if s.decideEnd(e, reason) {
		e.rc.End(errConnEnded)
	}
	if hook := onConnEnd.Load(); hook != nil {
		(*hook)(reason)
	}
	if isDesktopKind(c.adm.Load().Kind) {
		c.logDesktopEnd(reason)
	}
	ended := c.end(reason)
	_ = sc.Close()
	<-ended
	wg.Wait()
	// After every forward recorded its close.
	c.fwd.finish()
}

// end decides the connection's end, ends the forwards and ends every open
// channel, telling the client why when there is a reason: on a session
// channel's stderr, on a desktop channel by end@localport.io. It waits at
// most endWriteTimeout for those writes, which a client that stopped reading
// blocks; the caller then closes the connection, which fails a write still
// waiting, and receives from the returned channel once every write is done.
func (c *conn) end(reason string) <-chan struct{} {
	c.mu.Lock()
	c.ended = true
	open := make([]*channel, 0, len(c.channels))
	for ch := range c.channels {
		open = append(open, ch)
	}
	c.mu.Unlock()
	c.fwd.end()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for _, ch := range open {
			wg.Go(func() { ch.end(reason) })
		}
		wg.Go(func() { c.endDesktop(reason) })
		wg.Wait()
	}()
	bound := time.NewTimer(endWriteTimeout)
	defer bound.Stop()
	select {
	case <-done:
	case <-bound.C:
	}
	return done
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

// accept serves the connection's channel opens: on a desktop connection its
// one channel (desktop.go); otherwise session channels, at most maxChannels
// open and one in all on a terminal connection, and the local port
// forwarding channels (forward.go, their own bounds). On a recorded
// connection every session channel opens its own recording.
func (c *conn) accept(chans <-chan ssh.NewChannel, wg *sync.WaitGroup) {
	for nc := range chans {
		// A connection's kind holds for its life: a resume keeps it.
		if kind := c.adm.Load().Kind; isDesktopKind(kind) {
			c.openDesktop(nc, kind, wg)
			continue
		}
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
		single := c.adm.Load().Kind == "terminal"
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
	if kind := c.adm.Load().Kind; c.open == 0 && (kind == "terminal" || kind == "files") && !c.ended {
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
