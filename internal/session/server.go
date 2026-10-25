package session

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/recording"
)

// Refusal codes of the agent's refused first frame, beside the ticket codes.
const (
	CodeTicketReplayed  = "ticket_replayed"
	CodeKindDisabled    = "kind_disabled"
	CodeLoginNotAllowed = "login_not_allowed"
	CodeKindUnavailable = "kind_unavailable"
	// CodeAgentBusy is retryable: no acknowledged registration, the session
	// cap, a full or unavailable replay cache, a local handshake failure, or a
	// server that is shutting down.
	CodeAgentBusy = "agent_busy"
	// CodeRecordingKeyMismatch is retryable: the ticket's rec names a team
	// recording key other than the one the agent holds after one key refresh.
	CodeRecordingKeyMismatch = "recording_key_mismatch"
)

// Close reasons the agent sends, beside CodeProtocolError.
const (
	CloseIdle     = "idle"
	CloseShutdown = "shutdown"
	// CloseExited follows the kind's exit message when the process it serves
	// ended by itself.
	CloseExited = "exited"
)

const (
	maxSessions    = 8
	maxTicketBytes = 8 << 10
	maxFirstFrame  = 4 << 10
	// firstFrameTimeout bounds the agent's first frame from the stream's
	// start, as the edge waits for it.
	firstFrameTimeout = 10 * time.Second
	keyRefreshTimeout = 3 * time.Second
	idleTimeout       = 30 * time.Minute
	closeWriteTimeout = 2 * time.Second
	closeDrainTimeout = 2 * time.Second
)

// ticketReadTimeout bounds the ticket read from the stream's start. A
// variable so the timeout test runs in milliseconds.
var ticketReadTimeout = 5 * time.Second

// ServerConfig is one device's session server configuration. Capabilities,
// Logins and Desktop are the device's local config; nothing from the network
// widens them.
type ServerConfig struct {
	// Prefix is the device prefix tickets must name.
	Prefix string
	// Certificate returns the certificate, with its key, of the device's last
	// acknowledged registration; tickets are bound to it.
	Certificate func() (*tls.Certificate, bool)
	// Lookup returns a ticket verification key.
	Lookup Lookup
	// RefreshKeys fetches the ticket key set and recording key; called once
	// for an unknown kid and once for a rec naming a key other than the held
	// one.
	RefreshKeys func(ctx context.Context) error
	// RecordingKey returns the held team recording public key and its
	// SHA-256; ok is false when none is held. Nil holds none.
	RecordingKey func() (key []byte, sum [sha256.Size]byte, ok bool)
	// Capabilities are the enabled config.Capability values.
	Capabilities []string
	Logins       []string
	// Desktop lists the configured desktop targets: rdp, vnc.
	Desktop []string
	// JTI is the device identity's replay cache.
	JTI *JTILog
	// OnEvent receives one line per notable failure. Optional.
	OnEvent func(string)
	// Uploader delivers the recordings of tickets with rec; nil leaves
	// recording unavailable: Strict tickets are refused
	// CodeRecordingUnavailable and Best effort sessions run unrecorded.
	Uploader *recording.Uploader
	// Identifier is the device's identity (identity.Ref.Identity), kept in
	// each recording's spool metadata.
	Identifier string

	// clock replaces the wall clock for expiry and idle checks. Tests set it.
	clock clock
}

// clock is the time source of the expiry and idle checks. NewTimer returns
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
// tunnel.SessionHandler: Shutdown sends close {shutdown} to the streams
// holding a session slot, refuses agent_busy the streams past their ticket
// read without a slot and those arriving while it runs, resets the streams
// still reading their ticket, and leaves the server usable for the next
// control session once it returns.
type Server struct {
	cfg ServerConfig
	// kinds maps a ticket kind to the kind that serves it, nil when this
	// build serves none; kindFor in production. Tests replace it before the
	// first Serve.
	kinds func(kind string) prepareKind
	// users resolves a ticket's login to its account (lookupUser in
	// production) and euid returns the agent's effective uid (os.Geteuid).
	// Tests replace both before the first Serve.
	users func(ctx context.Context, login string) (*userRecord, error)
	euid  func() int

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
	// stop is closed by Shutdown. reading is set until the ticket read ends.
	// stopped and reading are guarded by mu.
	stop    chan struct{}
	stopped bool
	reading bool
}

// kindSession serves the records of one accepted session after its start.
// Handle is called from the session's reader goroutine only.
type kindSession interface {
	// Handle receives every record that is not close or activity. A record read
	// after the server recorded the session's end never reaches it; one checked
	// just before may, concurrently with End. An *Error with CodeProtocolError
	// ends the session with that close reason; any other error ends the
	// transport.
	Handle(m Message) error
	// Ended delivers the close reason, at most once and without blocking the
	// kind, when the kind ends the session by itself; an empty reason ends it
	// without an agent close. A nil channel means the kind never does.
	Ended() <-chan string
	// End is called exactly once when the session ends for any reason other
	// than Ended. It may run while Handle is in progress, must make a blocked
	// Handle return, stops the kind's output and returns without waiting.
	End()
	// Wait returns once the kind's goroutines have ended. It is called once,
	// after Ended delivered or End returned, and before the session's slot is
	// released.
	Wait()
}

// userRecord is the account a kind runs as, resolved by Server.resolveUser.
// Groups starts with GID. Shell is empty when the lookup gives none (macOS
// with the agent as root).
type userRecord struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
	Home   string
	Shell  string
}

// newKind starts a session from its start record body for the ticket's login.
// user is the account the server resolved for login, nil when it resolved
// none. Writes go through ch.
// rec records the session, nil when it is not recorded.
type newKind func(ch *Channel, start []byte, login string, user *userRecord, rec *sessionRecorder) (kindSession, error)

// prepareKind is a kind's check-time step: it runs after the user lookup and
// before Accept and the spend, and returns the session's constructor. root
// reports whether the agent runs as root; log writes one line to the
// server's OnEvent and stays usable after the session ended. An error
// refuses the ticket unspent with its *Error code (kind_unavailable
// otherwise); the server logs it.
type prepareKind func(login string, user *userRecord, root bool, log func(format string, args ...any)) (newKind, error)

// NewServer returns the session server of one device.
func NewServer(cfg ServerConfig) *Server {
	if cfg.clock == nil {
		cfg.clock = wallClock{}
	}
	return &Server{cfg: cfg, kinds: kindFor, users: lookupUser, euid: os.Geteuid, handlers: map[*handler]struct{}{}}
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

// refusedFrame is the first frame of a refused stream; the edge maps its code
// to the session's end reason.
type refusedFrame struct {
	Type string `json:"type"`
	Code string `json:"code"`
}

// Serve runs one session stream to its end. The caller closes stream after
// Serve returns.
func (s *Server) Serve(stream net.Conn) {
	start := time.Now()
	_ = stream.SetReadDeadline(start.Add(ticketReadTimeout))
	_ = stream.SetWriteDeadline(start.Add(firstFrameTimeout))
	h := &handler{stream: stream, stop: make(chan struct{}), reading: true}
	s.register(h)
	defer s.unregister(h)
	defer func() {
		if r := recover(); r != nil {
			s.log("session: handler panic: %v", r)
			_ = stream.Close()
		}
	}()

	raw, err := readTicket(stream)
	if err != nil {
		return
	}
	if !s.endTicketRead(h) {
		return
	}
	t, signer, prepare, code := s.check(raw)
	if code != "" {
		refuse(stream, code)
		return
	}
	if !s.takeSlot(h) {
		refuse(stream, CodeAgentBusy)
		return
	}
	defer s.releaseSlot()
	// The lookup runs under the slot, so at most maxSessions run at once, and
	// before the spend, so every refusal leaves the ticket unspent.
	user, code := s.resolveUser(t.Login, start)
	if code != "" {
		refuse(stream, code)
		return
	}
	kind, err := prepare(t.Login, user, s.euid() == 0, s.log)
	if err != nil {
		s.log("session: %v", err)
		refuse(stream, errorCode(err, CodeKindUnavailable))
		return
	}
	// Accept runs before the spend so a handshake failure leaves the ticket
	// unspent: a bad client key is the ticket's fault, a local failure is
	// retryable.
	msg, keys, err := Accept(t, signer)
	if err != nil {
		s.log("session: accept: %v", err)
		refuse(stream, errorCode(err, CodeAgentBusy))
		return
	}
	if err := s.cfg.JTI.Spend(t.JTI, time.Unix(t.EXP, 0).Add(jtiHold)); err != nil {
		code := CodeTicketReplayed
		if !errors.Is(err, errReplayed) {
			code = CodeAgentBusy
			s.log("session: the replay log cannot record the ticket: %v", err)
		}
		refuse(stream, code)
		return
	}
	var rec *sessionRecorder
	if t.Rec != nil && t.Rec.Policy == RecPolicyStrict {
		// Before the accept frame, so a recording that cannot open refuses the
		// session before any shell exists.
		if rec, err = s.startRecording(t, start); err != nil {
			s.log("session: %v", err)
			refuse(stream, CodeRecordingUnavailable)
			return
		}
	}
	if err := writeFrame(stream, msg); err != nil {
		rec.abort()
		return
	}
	_ = stream.SetWriteDeadline(time.Time{})
	if t.Rec != nil && t.Rec.Policy == RecPolicyBestEffort {
		if rec, err = s.startRecording(t, start); err != nil {
			s.log("session: the session runs unrecorded: %v", err)
		}
	}
	ch, err := keys.AgentChannel(stream)
	if err != nil {
		s.log("session: %v", err)
		rec.end()
		return
	}
	s.run(h, ch, kind, t.Login, user, rec)
}

// check verifies the ticket and the local config. It spends nothing. A
// non-empty code refuses the stream.
func (s *Server) check(raw []byte) (*Ticket, crypto.Signer, prepareKind, string) {
	cert, ok := s.cfg.Certificate()
	if !ok {
		return nil, nil, nil, CodeAgentBusy
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok || len(cert.Certificate) == 0 {
		return nil, nil, nil, CodeAgentBusy
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil, nil, nil, CodeAgentBusy
		}
	}
	device := Device{Prefix: s.cfg.Prefix, SPKISHA256: SPKIHash(leaf.RawSubjectPublicKeyInfo)}
	t, err := VerifyTicket(raw, s.cfg.Lookup, device, s.cfg.clock.Now())
	if errorCode(err, "") == CodeTicketUnknownKey && s.cfg.RefreshKeys != nil {
		ctx, cancel := context.WithTimeout(context.Background(), keyRefreshTimeout)
		if rerr := s.cfg.RefreshKeys(ctx); rerr != nil {
			s.log("session: ticket key refresh for an unknown kid: %v", rerr)
		}
		cancel()
		t, err = VerifyTicket(raw, s.cfg.Lookup, device, s.cfg.clock.Now())
	}
	if err != nil {
		// Refusals of a validly signed ticket are logged with their details:
		// a clock refusal names the difference, which a device without a
		// real-time clock needs. Unsigned input is not logged, so it cannot
		// flood the log.
		if code := errorCode(err, ""); code == CodeTicketExpired || code == CodeTicketWrongDevice {
			s.log("session: ticket refused: %v", err)
		}
		return nil, nil, nil, errorCode(err, CodeTicketInvalid)
	}
	if !s.kindEnabled(t.Kind) {
		return nil, nil, nil, CodeKindDisabled
	}
	if t.Login != "" && !slices.Contains(s.cfg.Logins, t.Login) {
		return nil, nil, nil, CodeLoginNotAllowed
	}
	kind := s.kinds(t.Kind)
	if kind == nil {
		return nil, nil, nil, CodeKindUnavailable
	}
	if t.Rec != nil {
		if t.Kind != "terminal" {
			return nil, nil, nil, CodeKindUnavailable
		}
		if !s.recordingKeyMatches(t.Rec.PubSHA256) {
			return nil, nil, nil, CodeRecordingKeyMismatch
		}
	}
	return t, signer, kind, ""
}

// recordingKeyMatches reports whether the held recording key hashes to want
// (unpadded base64url), refreshing the keys once when it does not. A refresh
// the key refresher declines leaves the held key, so the mismatch stands.
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

// kindEnabled maps a ticket kind to the capability that enables it: terminal
// and ssh need terminal, files needs files, rdp and vnc need desktop and
// their configured target.
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

func errorCode(err error, fallback string) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return fallback
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

// endTicketRead ends h's ticket read, after which Shutdown no longer resets
// the stream and it is refused agent_busy at takeSlot instead. It reports
// false when Shutdown reset the stream during the read.
func (s *Server) endTicketRead(h *handler) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.stopped {
		return false
	}
	h.reading = false
	_ = h.stream.SetReadDeadline(time.Time{})
	return true
}

// takeSlot takes one of the maxSessions slots unless Shutdown is running or
// has stopped h. A slotted stream is ended by close {shutdown} from run.
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

// Shutdown stops every Serve call and waits for them or ctx. A stream holding
// a slot gets close {shutdown}; one past its ticket read without a slot, and
// any stream reaching the slot check while Shutdown runs, is refused
// agent_busy; one still reading its ticket is reset. Serve calls after it
// returns are served.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing++
	for h := range s.handlers {
		if h.stopped {
			continue
		}
		h.stopped = true
		close(h.stop)
		if h.reading {
			// Expires the ticket read at once; endTicketRead then ends Serve.
			_ = h.stream.SetReadDeadline(time.Now())
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

// sessionEnd is how the reader ended a session. reason, when set, is the
// close reason the agent sends.
type sessionEnd struct {
	reason string
}

// session is the state of one accepted session that run shares with its
// reader goroutine.
type session struct {
	ch    *Channel
	kind  newKind
	login string
	user  *userRecord
	rec   *sessionRecorder
	// started receives the kind once the reader handed it over.
	started      chan kindSession
	lastActivity atomic.Int64

	// mu orders the reader's handoff of the kind, and its check before each
	// Handle, against run's end decision. It is not held while Handle runs.
	mu    sync.Mutex
	k     kindSession
	ended bool
}

// setKind hands k over unless the end is already recorded; on false the
// caller ends and joins k itself.
func (ss *session) setKind(k kindSession) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.ended {
		return false
	}
	ss.k = k
	return true
}

// end records the session's end and returns the kind handed over, nil when
// there is none. A record read after it is not passed to Handle.
func (ss *session) end() kindSession {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.ended = true
	return ss.k
}

// open reports whether the session's end is not recorded yet.
func (ss *session) open() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return !ss.ended
}

// run serves an accepted session until its first recorded end, then ends the
// kind (End unless the kind ended the session itself), sends the agent's close
// when the end has a reason, joins the reader and the kind, and then ends the
// recording, after the kind's last tap.
func (s *Server) run(h *handler, ch *Channel, kind newKind, login string, user *userRecord, rec *sessionRecorder) {
	defer rec.end()
	ss := &session{ch: ch, kind: kind, login: login, user: user, rec: rec, started: make(chan kindSession, 1)}
	ss.lastActivity.Store(s.cfg.clock.Now().UnixNano())
	ended := make(chan sessionEnd, 1)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer func() {
			if r := recover(); r != nil {
				s.log("session: reader panic: %v", r)
				ended <- sessionEnd{}
			}
		}()
		ended <- s.read(ss)
	}()

	fire, stopTimer := s.cfg.clock.NewTimer(idleTimeout)
	var kindEnded <-chan string
	var reason string
	selfEnd := false
wait:
	for {
		select {
		case k := <-ss.started:
			kindEnded = k.Ended()
		case reason = <-kindEnded:
			selfEnd = true
			break wait
		case e := <-ended:
			reason = e.reason
			break wait
		case <-h.stop:
			reason = CloseShutdown
			break wait
		case <-rec.failedC():
			reason = CloseRecordingFailed
			break wait
		case <-fire:
			idle := s.cfg.clock.Now().Sub(time.Unix(0, ss.lastActivity.Load()))
			if idle >= idleTimeout {
				reason = CloseIdle
				break wait
			}
			fire, stopTimer = s.cfg.clock.NewTimer(idleTimeout - idle)
		}
	}
	stopTimer()
	k := ss.end()
	if k != nil && !selfEnd {
		k.End()
	}
	if reason == "" {
		// Client close, truncation or a failed write: no agent close.
		_ = h.stream.Close()
		<-readerDone
	} else {
		s.closeSession(h.stream, ch, reason, readerDone)
	}
	if k != nil {
		k.Wait()
	}
}

// read reads records until the session ends. The first must be start.
func (s *Server) read(ss *session) sessionEnd {
	m, err := ss.ch.ReadMessage()
	if err != nil {
		return endOf(err)
	}
	if m.Type != TypeStart {
		return sessionEnd{reason: CodeProtocolError}
	}
	k, err := ss.kind(ss.ch, m.Body, ss.login, ss.user, ss.rec)
	if err != nil {
		return endOf(err)
	}
	if !ss.setKind(k) {
		// run recorded the end while the kind started.
		k.End()
		k.Wait()
		return sessionEnd{}
	}
	ss.started <- k
	active := func() { ss.lastActivity.Store(s.cfg.clock.Now().UnixNano()) }
	active()
	for {
		m, err := ss.ch.ReadMessage()
		if err != nil {
			return endOf(err)
		}
		switch m.Type {
		case TypeClose:
			return sessionEnd{}
		case TypeActivity:
			active()
			continue
		case TypeData:
			active()
		}
		if !ss.open() {
			return sessionEnd{}
		}
		if err := k.Handle(m); err != nil {
			return endOf(err)
		}
	}
}

// endOf maps a read or kind error to the session's end: a protocol error is
// answered with close {protocol_error}; anything else ends the transport.
func endOf(err error) sessionEnd {
	if errorCode(err, "") == CodeProtocolError {
		return sessionEnd{reason: CodeProtocolError}
	}
	return sessionEnd{}
}

// closeSession sends close {reason} within closeWriteTimeout, half-closes
// the stream and reads it to its end within closeDrainTimeout, so the record
// reaches the client before the stream is reset.
func (s *Server) closeSession(stream net.Conn, ch *Channel, reason string, readerDone <-chan struct{}) {
	_ = stream.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	if err := ch.WriteClose(reason); err == nil {
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	drain := time.NewTimer(closeDrainTimeout)
	defer drain.Stop()
	select {
	case <-readerDone:
		// The reader stopped (protocol error, client close, stream end):
		// drain the rest here.
		_ = stream.SetReadDeadline(time.Now().Add(closeDrainTimeout))
		_, _ = io.Copy(io.Discard, stream)
	case <-drain.C:
		_ = stream.Close()
		<-readerDone
	}
}

// refuse sends the refused frame and delivers it as closeSession delivers its
// close record: a half-close, then the stream read to its end within
// closeDrainTimeout, because the caller's Close resets the stream and drops
// bytes the edge has not read yet.
func refuse(stream net.Conn, code string) {
	if err := writeFrame(stream, refusedFrame{Type: "refused", Code: code}); err != nil {
		return
	}
	if cw, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	// The drain deadline bounds the rest; an expired write deadline would
	// reset the stream before the frame is out.
	_ = stream.SetWriteDeadline(time.Time{})
	_ = stream.SetReadDeadline(time.Now().Add(closeDrainTimeout))
	_, _ = io.Copy(io.Discard, stream)
}

// readTicket reads the uint32-prefixed ticket of at most maxTicketBytes.
func readTicket(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxTicketBytes {
		return nil, fmt.Errorf("ticket of %d bytes", n)
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// writeFrame writes v as the uint32-prefixed JSON first frame.
func writeFrame(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFirstFrame {
		return fmt.Errorf("first frame of %d bytes", len(body))
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	_, err = w.Write(frame)
	return err
}
