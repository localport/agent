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
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

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
	handlers map[*handler]struct{}
	// drained is closed when handlers becomes empty while Shutdown waits.
	drained chan struct{}
}

// handler is one Serve call.
type handler struct {
	stream net.Conn
	// stop is closed by Shutdown, after stopReason is set. stopped,
	// stopReason and handshaking are guarded by mu; stopReason is read
	// without it once stop is closed, as it is never written again.
	stop        chan struct{}
	stopped     bool
	stopReason  string
	handshaking bool
}

// NewServer returns the session server of one device.
func NewServer(cfg ServerConfig) *Server {
	if cfg.clock == nil {
		cfg.clock = wallClock{}
	}
	return &Server{cfg: cfg, launcher: launcherFor(cfg.Launcher), handlers: map[*handler]struct{}{}}
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

// Serve runs one SSH connection on stream to its end. id is the connection's
// session id (its recording id) and serial the certificate serial the edge
// admitted. A refused stream is closed without a message: an SSH client
// sees a failed handshake or userauth. The caller closes stream after Serve
// returns.
func (s *Server) Serve(stream net.Conn, id [16]byte, serial uint64) {
	start := s.cfg.clock.Now()
	h := &handler{stream: stream, stop: make(chan struct{}), handshaking: true}
	s.register(h)
	defer s.unregister(h)
	defer func() {
		if r := recover(); r != nil {
			s.log("session: handler panic: %v", r)
			_ = stream.Close()
		}
	}()
	if !s.takeSlot(h) {
		return
	}
	defer s.releaseSlot()

	_ = stream.SetDeadline(time.Now().Add(handshakeTimeout))
	cfg, err := s.serverConfig(serial)
	if err != nil {
		s.log("session: %v", err)
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(stream, cfg)
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
	adm := admissionOf(conn.Permissions)
	idText := uuidText(id)

	var rec *sessionRecorder
	if adm.Rec != nil {
		rec, err = s.startRecording(idText, adm, start)
		if err != nil {
			if adm.Rec.Policy == RecPolicyStrict {
				// Before any channel, so no shell runs unrecorded.
				s.log("session: %s: closed: %v", idText, err)
				return
			}
			s.log("session: %s runs unrecorded: %v", idText, err)
		}
	}
	defer rec.end()
	s.run(h, conn, chans, reqs, adm, rec)
}

// serverConfig is one connection's SSH server configuration. Its callbacks
// keep no state across connections or attempts: the identity is built in
// VerifiedPublicKeyCallback, after possession of the certificate's key is
// proven, and returned as the connection's Permissions.
func (s *Server) serverConfig(serial uint64) (*ssh.ServerConfig, error) {
	cert, ok := s.cfg.Certificate()
	if !ok || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no acknowledged registration to serve sessions with")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the device key cannot sign")
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, fmt.Errorf("device certificate: %w", err)
		}
	}
	hostKey, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("host key: %w", err)
	}
	device := Device{Prefix: s.cfg.Prefix, SPKISHA256: SPKIHash(leaf.RawSubjectPublicKeyInfo)}
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM},
			MACs:         []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM},
		},
		ServerVersion: serverVersion,
		MaxAuthTries:  3,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if _, ok := key.(*ssh.Certificate); !ok {
				return nil, refuseCert("a plain key, not a certificate")
			}
			return &ssh.Permissions{}, nil
		},
		VerifiedPublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey, _ *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			adm, err := s.admit(key.(*ssh.Certificate), meta.User(), device, serial)
			if err != nil {
				s.log("session: userauth refused: %v", err)
				return nil, err
			}
			return adm.permissions(), nil
		},
	}
	cfg.AddHostKey(hostKey)
	return cfg, nil
}

// admit verifies cert (refreshing the CA keys once for an unknown CA) and
// applies the local config: the kind enabled and served by this build, the
// login enabled, and a recording key that matches.
func (s *Server) admit(cert *ssh.Certificate, user string, device Device, serial uint64) (*admission, error) {
	verify := func() (*admission, error) {
		return verifyCert(cert, user, s.caKeys(), device, serial, s.cfg.clock.Now())
	}
	adm, err := verify()
	if err != nil && s.cfg.RefreshKeys != nil && !signedByCA(cert, s.caKeys()) {
		ctx, cancel := context.WithTimeout(context.Background(), keyRefreshTimeout)
		if rerr := s.cfg.RefreshKeys(ctx); rerr != nil {
			s.log("session: CA key refresh for an unknown CA key: %v", rerr)
		}
		cancel()
		adm, err = verify()
	}
	if err != nil {
		return nil, err
	}
	switch {
	case !s.kindEnabled(adm.Kind):
		return nil, refuseCert("kind %q is not enabled on this device", adm.Kind)
	case adm.Kind != "terminal" && adm.Kind != "ssh":
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
// through h.stop. It reports false when Shutdown aborted the handshake.
func (s *Server) endHandshake(h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.stopped {
		return false
	}
	h.handshaking = false
	_ = h.stream.SetDeadline(time.Time{})
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
			// Expires the handshake at once; endHandshake then ends Serve.
			_ = h.stream.SetDeadline(time.Now())
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
	s     *Server
	adm   *admission
	rec   *sessionRecorder
	login string

	lastActivity atomic.Int64

	mu sync.Mutex
	// open counts the channels accepted and not yet closed; served counts
	// every channel accepted. ended is set once the connection's end is
	// decided; no channel is accepted after it.
	open     int
	served   int
	ended    bool
	channels map[*channel]struct{}
	// recStarted is set once a channel started the recording's cast.
	recStarted bool
	// allClosed receives once when a terminal connection's channel closed.
	allClosed chan struct{}
}

func (c *conn) active() { c.lastActivity.Store(c.s.cfg.clock.Now().UnixNano()) }

// run serves an admitted connection until its first recorded end: the client
// closing it, the idle timeout, a Shutdown, a failed Strict recording, or the
// channel of a terminal connection closing. It then writes the reason to
// every open channel's stderr, closes the connection and joins the channels.
func (s *Server) run(h *handler, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, adm *admission, rec *sessionRecorder) {
	c := &conn{s: s, adm: adm, rec: rec, login: sc.User(), channels: map[*channel]struct{}{}, allClosed: make(chan struct{}, 1)}
	c.active()
	var wg sync.WaitGroup
	clientDone := make(chan struct{})
	wg.Go(func() {
		defer close(clientDone)
		c.accept(chans, &wg)
	})
	wg.Go(func() {
		// Global requests: keepalives count as activity; every request is
		// refused (no forwarding).
		for r := range reqs {
			c.active()
			if r.WantReply {
				_ = r.Reply(false, nil)
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
		case <-rec.failedC():
			reason = CloseRecordingFailed
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
	c.end(reason)
	_ = sc.Close()
	wg.Wait()
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
}

// accept serves the connection's channel opens: session channels only, at
// most maxChannels open, and one in all on a terminal or recorded connection.
func (c *conn) accept(chans <-chan ssh.NewChannel, wg *sync.WaitGroup) {
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "only session channels are served")
			continue
		}
		c.mu.Lock()
		// A terminal connection, and a recorded one of any kind, serves one
		// channel in its life: the recording's cast follows one channel, so a
		// second channel would run unrecorded.
		single := c.adm.Kind == "terminal" || c.rec != nil
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

// channelClosed forgets ch; the last channel of a terminal connection ends it.
func (c *conn) channelClosed(ch *channel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.channels, ch)
	c.open--
	if c.open == 0 && c.adm.Kind == "terminal" && !c.ended {
		select {
		case c.allClosed <- struct{}{}:
		default:
		}
	}
}

// claimRecording reports whether the caller's channel is the one whose
// terminal the recording's cast follows: the first channel that starts.
func (c *conn) claimRecording() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rec == nil || c.recStarted {
		return false
	}
	c.recStarted = true
	return true
}

// uuidText is id in canonical lowercase UUID form.
func uuidText(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
