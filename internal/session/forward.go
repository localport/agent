package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/localport/agent/internal/launcher"
)

// beforeListenerRegistration, when set by a test, runs in listen once the
// helper bound listener l and before l is registered.
var beforeListenerRegistration atomic.Pointer[func(*forwarder, *remoteListener)]

// Port forwarding on an ssh connection (RFC 4254 7; OpenSSH PROTOCOL 2.4 for
// unix sockets). A forward needs the device's forwarding capability and the
// certificate's extension for its direction. Every dial and listen runs in
// the connection's networking helper, as the login; the agent relays each
// forward between its SSH channel and the socket (or, on Windows, the
// helper's stream) and records open and close events, never the bytes.
const (
	// maxForwardChannels bounds the forward channels (local and forwarded)
	// open on one connection; with the 2 MiB SSH channel window each, a
	// stalled connection holds at most 64 MiB.
	maxForwardChannels = 32
	// maxRemoteListeners bounds one connection's remote listeners.
	maxRemoteListeners = 8
	// maxDeviceForwards bounds the forward channels of every connection of
	// the device together.
	maxDeviceForwards = 64
	// forwardRequestTimeout bounds one dial or listen in the helper.
	forwardRequestTimeout = 35 * time.Second
)

// Channel types and global requests of port forwarding.
const (
	chanDirectTCPIP          = "direct-tcpip"
	chanDirectStreamLocal    = "direct-streamlocal@openssh.com"
	chanForwardedTCPIP       = "forwarded-tcpip"
	chanForwardedStreamLocal = "forwarded-streamlocal@openssh.com"
	reqTCPIPForward          = "tcpip-forward"
	reqCancelTCPIPForward    = "cancel-tcpip-forward"
	reqStreamLocalForward    = "streamlocal-forward@openssh.com"
	reqCancelStreamLocal     = "cancel-streamlocal-forward@openssh.com"
)

// unixForwardSupported reports whether unix socket forwards are served:
// Linux and macOS, not Windows.
var unixForwardSupported = runtime.GOOS != "windows"

// errForwardRecording refuses a forward of a Strict connection whose
// forwards recording could not open.
var errForwardRecording = errors.New(CodeRecordingUnavailable)

// forwardEvent is one "p" event of a connection's forwards recording. Op is
// listen or unlisten for a remote listener, open or close for one forwarded
// connection. Result is "ok" or the refusal's code on listen and open; In
// and Out (bytes from the client toward the target, and back) are set on
// close only.
type forwardEvent struct {
	Op     string `json:"op"`
	Dir    string `json:"dir"`
	Kind   string `json:"kind"`
	Addr   string `json:"addr"`
	Origin string `json:"origin,omitempty"`
	Result string `json:"result,omitempty"`
	In     *int64 `json:"in,omitempty"`
	Out    *int64 `json:"out,omitempty"`
}

// remoteListener is one tcpip-forward or streamlocal-forward the helper
// serves: the bind address as the client named it and the bound port, or
// the socket path.
type remoteListener struct {
	id   uint32
	kind string
	addr string
	port uint32
	path string
	// keys are the listener's entries in forwarder.listeners: the bind
	// address with the requested port, or with the bound port for a port 0
	// request; a cancel names one of them.
	keys []string
	// ready is closed once listen settled id, port and keys; a connection
	// the helper accepted before that waits for it.
	ready chan struct{}
}

// forwarder is one connection's port forwarding: its networking helper,
// started at the first allowed forward and owned by the connection, its
// forwards recording, and its remote listeners. Lock order: conn.mu, then
// Server.mu.
type forwarder struct {
	c  *conn
	sc *ssh.ServerConn
	wg *sync.WaitGroup
	// stop is closed when the connection ends: dials in flight are
	// cancelled and a Strict tap waiting for queue space returns.
	stop    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	endOnce sync.Once

	// startMu serializes the helper's start.
	startMu sync.Mutex

	// The fields below are guarded by c.mu.
	client  *launcher.ForwardClient
	session *launcher.Session
	rec     *sessionRecorder
	// recAttempted is set with client when its start tried to record.
	recAttempted bool
	failed       bool
	open         int
	listeners    map[string]*remoteListener
	// conns are the relayed connections, each true for the remote direction.
	conns map[launcher.ForwardConn]bool
}

func newForwarder(c *conn, sc *ssh.ServerConn, wg *sync.WaitGroup) *forwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &forwarder{c: c, sc: sc, wg: wg, stop: make(chan struct{}), ctx: ctx, cancel: cancel,
		listeners: map[string]*remoteListener{}, conns: map[launcher.ForwardConn]bool{}}
}

// allowed reports whether the connection may forward in the local or remote
// direction: an ssh connection, the device's forwarding capability, and the
// extension of the certificate the connection runs under.
func (f *forwarder) allowed(remote bool) bool {
	a := f.c.adm.Load()
	if a.Kind != "ssh" || !slices.Contains(f.c.s.cfg.Capabilities, "forwarding") {
		return false
	}
	if remote {
		return a.ForwardRemote
	}
	return a.ForwardLocal
}

// reserve takes one forward channel slot of the connection and the device.
func (f *forwarder) reserve() bool {
	c, s := f.c, f.c.s
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ended || f.open >= maxForwardChannels {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.forwards >= maxDeviceForwards {
		return false
	}
	f.open++
	s.forwards++
	return true
}

func (f *forwarder) release() {
	c, s := f.c, f.c.s
	c.mu.Lock()
	defer c.mu.Unlock()
	f.open--
	s.mu.Lock()
	s.forwards--
	s.mu.Unlock()
}

// ensure returns the connection's helper, starting it and the forwards
// recording at the first call. A start that fails (launcher refusal, Strict
// recording unavailable) fails every later forward of the connection, as a
// helper that exits does.
func (f *forwarder) ensure() (*launcher.ForwardClient, error) {
	c, s := f.c, f.c.s
	f.startMu.Lock()
	defer f.startMu.Unlock()
	c.mu.Lock()
	client, failed, ended := f.client, f.failed, c.ended
	c.mu.Unlock()
	switch {
	case ended, failed:
		return nil, errors.New(CloseHelperFailed)
	case client != nil:
		return client, nil
	}
	fail := func(err error) (*launcher.ForwardClient, error) {
		c.mu.Lock()
		f.failed = true
		c.mu.Unlock()
		return nil, err
	}
	var rec *sessionRecorder
	attempted := false
	if a := c.adm.Load(); a.Rec != nil {
		attempted = true
		var err error
		rec, err = s.startRecording(uuidText(newRecordingID()), a.sessionID, a.admission, s.cfg.clock.Now(), a.recordedStarts.Add(1))
		if err != nil {
			if a.Rec.Policy == RecPolicyStrict {
				s.log("session: %s: forwarding refused: %v", a.sessionID, err)
				return fail(errForwardRecording)
			}
			s.log("session: %s: forwards run unrecorded: %v", a.sessionID, err)
		}
	}
	ours, theirs, pipe, err := newSessionChannel()
	if err != nil {
		rec.abort()
		s.log("session: forward channel: %v", err)
		return fail(errors.New(CodeKindUnavailable))
	}
	req := launcher.Request{Kind: launcher.KindForward, Device: s.cfg.Device, Login: c.login, Pipe: pipe}
	if len(c.password) > 0 {
		// The launcher client zeroes its copy once sent.
		req.HasPassword, req.Password = true, bytes.Clone(c.password)
	}
	ctx, cancel := context.WithTimeout(f.ctx, startTimeout)
	sess, err := s.launcher.Start(ctx, req, theirs)
	cancel()
	if theirs != nil {
		_ = theirs.Close()
	}
	if err != nil {
		_ = ours.Close()
		rec.abort()
		s.log("session: the forward helper for %q did not start: %v", c.login, err)
		return fail(errors.New(refusalReason(err)))
	}
	client, err = launcher.NewForwardClient(ours, s.log)
	if err != nil {
		_ = sess.Close()
		rec.abort()
		s.log("session: the forward helper's channel: %v", err)
		return fail(errors.New(CloseHelperFailed))
	}
	c.mu.Lock()
	if c.ended {
		c.mu.Unlock()
		_ = client.Close()
		_ = sess.Close()
		rec.abort()
		return nil, errors.New(CloseHelperFailed)
	}
	// A resume that named a recording either finds this client published or
	// is seen here. A later forward starts under the new admission and
	// records, so this refusal does not set failed.
	if c.adm.Load().violatedBy(recordingStateOf(rec, attempted)) {
		c.mu.Unlock()
		_ = client.Close()
		_ = sess.Close()
		rec.abort()
		return nil, errors.New(CloseRecordingRequired)
	}
	f.client, f.session, f.rec, f.recAttempted = client, sess, rec, attempted
	c.mu.Unlock()
	rec.start(time.Now(), defaultCols, defaultRows)
	f.wg.Go(func() { f.watch(client, rec) })
	return client, nil
}

// watch ends the connection when its Strict forwards recording fails, and
// ends every forward when the helper ends; later forwards are refused.
func (f *forwarder) watch(client *launcher.ForwardClient, rec *sessionRecorder) {
	select {
	case <-rec.failedC():
		f.c.fail(CloseRecordingFailed)
		<-client.Done()
	case <-client.Done():
	}
	c := f.c
	c.mu.Lock()
	f.failed = true
	ended := c.ended
	conns := make([]launcher.ForwardConn, 0, len(f.conns))
	for fc := range f.conns {
		conns = append(conns, fc)
	}
	c.mu.Unlock()
	if !ended {
		c.s.log("session: %s: the forward helper ended; forwarding stops", c.adm.Load().sessionID)
	}
	for _, fc := range conns {
		_ = fc.Close()
	}
}

// recordingViolatedLocked reports whether the running helper cannot run under
// a. It runs with c.mu held.
func (f *forwarder) recordingViolatedLocked(a *connAdmission) bool {
	return f.client != nil && !f.failed && a.violatedBy(recordingStateOf(f.rec, f.recAttempted))
}

// track registers a relayed connection of the remote or local direction, so
// the helper's end or a resume that disallows the direction closes it; false
// when the helper already ended or the direction is no longer allowed.
func (f *forwarder) track(fc launcher.ForwardConn, remote bool) bool {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	if f.failed || f.c.ended || !f.allowed(remote) {
		return false
	}
	f.conns[fc] = remote
	return true
}

// disallowedLocked removes and returns what the connection's admission no
// longer allows: the relayed connections of a disallowed direction and, for
// remote, every listener, with the helper client that serves them. c.mu
// held; the admission is stored under the same lock, so a track or listen
// registration either sees it or is returned here.
func (f *forwarder) disallowedLocked() ([]launcher.ForwardConn, []*remoteListener, *launcher.ForwardClient) {
	local, remote := f.allowed(false), f.allowed(true)
	var conns []launcher.ForwardConn
	for fc, isRemote := range f.conns {
		if (isRemote && !remote) || (!isRemote && !local) {
			conns = append(conns, fc)
			delete(f.conns, fc)
		}
	}
	var listeners []*remoteListener
	if !remote {
		seen := map[*remoteListener]struct{}{}
		for k, l := range f.listeners {
			delete(f.listeners, k)
			if _, dup := seen[l]; !dup {
				seen[l] = struct{}{}
				listeners = append(listeners, l)
			}
		}
	}
	return conns, listeners, f.client
}

// closeDisallowed closes what disallowedLocked returned and records each
// listener's end; each relay records its own close.
func (f *forwarder) closeDisallowed(conns []launcher.ForwardConn, listeners []*remoteListener, client *launcher.ForwardClient) {
	for _, fc := range conns {
		_ = fc.Close()
	}
	for _, l := range listeners {
		client.CloseListener(l.id)
		f.record(forwardEvent{Op: "unlisten", Dir: "remote", Kind: l.kind, Addr: f.listenerAddr(l, uint16(l.port))})
	}
}

func (f *forwarder) untrack(fc launcher.ForwardConn) {
	f.c.mu.Lock()
	delete(f.conns, fc)
	f.c.mu.Unlock()
}

// end runs when the connection's end is decided: it cancels dials in flight
// and ends the helper, which closes its listeners. Relays end as the SSH
// connection closes.
func (f *forwarder) end() {
	f.endOnce.Do(func() {
		close(f.stop)
		f.cancel()
		f.c.mu.Lock()
		client := f.client
		f.c.mu.Unlock()
		if client != nil {
			_ = client.Close()
		}
	})
}

// finish runs after every forward goroutine returned: it ends the forwards
// recording and the launcher request.
func (f *forwarder) finish() {
	f.end()
	f.c.mu.Lock()
	rec, sess := f.rec, f.session
	f.c.mu.Unlock()
	rec.end()
	_ = sess.Close()
}

// record writes one forward event to the forwards recording, if any.
func (f *forwarder) record(ev forwardEvent) {
	f.c.mu.Lock()
	rec := f.rec
	f.c.mu.Unlock()
	if rec == nil {
		return
	}
	if line, err := json.Marshal(ev); err == nil {
		rec.forward(line, f.stop)
	}
}

// refusalCode is the code a failed forward reports to the client.
func refusalCode(err error) string {
	var r *launcher.ForwardRefusal
	switch {
	case errors.As(err, &r):
		return launcher.FwdCodeName(r.Code)
	case errors.Is(err, launcher.ErrForwardHelperFailed):
		return CloseHelperFailed
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return launcher.FwdCodeName(launcher.FwdCodeUnreachable)
	}
	return err.Error()
}

// local serves a direct-tcpip or direct-streamlocal channel open. It never
// blocks the connection's accept loop: the dial runs on its own goroutine.
func (f *forwarder) local(nc ssh.NewChannel) {
	if !f.allowed(false) {
		_ = nc.Reject(ssh.Prohibited, "port forwarding is not permitted")
		return
	}
	var network byte
	var host, path, kind, addr string
	var port uint16
	switch nc.ChannelType() {
	case chanDirectTCPIP:
		var p struct {
			Host     string
			Port     uint32
			OrigHost string
			OrigPort uint32
		}
		if ssh.Unmarshal(nc.ExtraData(), &p) != nil || p.Host == "" || len(p.Host) > launcher.MaxForwardHost ||
			bytes.IndexByte([]byte(p.Host), 0) >= 0 || p.Port < 1 || p.Port > 65535 {
			_ = nc.Reject(ssh.ConnectionFailed, launcher.FwdCodeName(launcher.FwdCodeInvalid))
			return
		}
		network, host, port, kind = launcher.FwdTCP, p.Host, uint16(p.Port), "tcp"
		addr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	default:
		if !unixForwardSupported {
			_ = nc.Reject(ssh.Prohibited, "unix socket forwarding is not served on this platform")
			return
		}
		var p struct {
			Path      string
			Reserved0 string
			Reserved1 uint32
		}
		if ssh.Unmarshal(nc.ExtraData(), &p) != nil || !launcher.ValidForwardPath(p.Path) {
			_ = nc.Reject(ssh.ConnectionFailed, launcher.FwdCodeName(launcher.FwdCodeInvalid))
			return
		}
		network, path, kind, addr = launcher.FwdUnix, p.Path, "unix", p.Path
	}
	if !f.reserve() {
		_ = nc.Reject(ssh.ResourceShortage, "forward limit reached")
		return
	}
	f.wg.Go(func() {
		defer f.release()
		ev := forwardEvent{Op: "open", Dir: "local", Kind: kind, Addr: addr}
		client, err := f.ensure()
		if err != nil {
			_ = nc.Reject(ssh.ConnectionFailed, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(f.ctx, forwardRequestTimeout)
		fc, err := client.Dial(ctx, network, host, port, path)
		cancel()
		if err != nil {
			ev.Result = refusalCode(err)
			f.record(ev)
			_ = nc.Reject(ssh.ConnectionFailed, ev.Result)
			return
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			_ = fc.Close()
			return
		}
		f.wg.Go(func() { ssh.DiscardRequests(reqs) })
		ev.Result = "ok"
		f.record(ev)
		f.relayAndRecord(ch, fc, forwardEvent{Op: "close", Dir: "local", Kind: kind, Addr: addr})
	})
}

// relayAndRecord relays one forward and records its close with the bytes
// each way.
func (f *forwarder) relayAndRecord(ch ssh.Channel, fc launcher.ForwardConn, closeEv forwardEvent) {
	var in, out int64
	if f.track(fc, closeEv.Dir == "remote") {
		in, out = f.c.relay(ch, fc)
		f.untrack(fc)
	} else {
		_ = fc.Close()
		_ = ch.Close()
	}
	closeEv.In, closeEv.Out = &in, &out
	f.record(closeEv)
}

// globalRequest answers one global request: the remote forwarding requests
// when allowed, false for every other.
func (f *forwarder) globalRequest(r *ssh.Request) (bool, []byte) {
	switch r.Type {
	case reqTCPIPForward, reqStreamLocalForward:
		if !f.allowed(true) {
			return false, nil
		}
		return f.listen(r)
	case reqCancelTCPIPForward, reqCancelStreamLocal:
		if !f.allowed(true) {
			return false, nil
		}
		return f.cancelListen(r), nil
	}
	return false, nil
}

func tcpListenerKey(addr string, port uint32) string {
	return "tcp\x00" + addr + "\x00" + strconv.FormatUint(uint64(port), 10)
}

func unixListenerKey(path string) string { return "unix\x00" + path }

// listen serves tcpip-forward (bound on loopback whatever address the client
// names; "::1" binds IPv6) and streamlocal-forward. A request for port 0
// gets the bound port in its reply (RFC 4254 7.1).
func (f *forwarder) listen(r *ssh.Request) (bool, []byte) {
	l := &remoteListener{}
	var network byte
	var port uint16
	var ipv6 bool
	if r.Type == reqTCPIPForward {
		var p struct {
			Addr string
			Port uint32
		}
		if ssh.Unmarshal(r.Payload, &p) != nil || p.Port > 65535 || len(p.Addr) > launcher.MaxForwardHost {
			return false, nil
		}
		network, port, ipv6 = launcher.FwdTCP, uint16(p.Port), p.Addr == "::1"
		l.kind, l.addr = "tcp", p.Addr
		if p.Port != 0 {
			l.keys = []string{tcpListenerKey(p.Addr, p.Port)}
		}
	} else {
		if !unixForwardSupported {
			return false, nil
		}
		var p struct{ Path string }
		if ssh.Unmarshal(r.Payload, &p) != nil || !launcher.ValidForwardPath(p.Path) {
			return false, nil
		}
		network, l.kind, l.path = launcher.FwdUnix, "unix", p.Path
		l.keys = []string{unixListenerKey(p.Path)}
	}
	l.ready = make(chan struct{})
	defer close(l.ready)
	c := f.c
	c.mu.Lock()
	full, dup := f.countListeners() >= maxRemoteListeners, len(l.keys) > 0 && f.listeners[l.keys[0]] != nil
	c.mu.Unlock()
	if dup || full {
		return false, nil
	}
	client, err := f.ensure()
	if err != nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(f.ctx, forwardRequestTimeout)
	id, bound, err := client.Listen(ctx, network, port, ipv6, l.path,
		func(a launcher.Accepted) { f.accepted(l, a) },
		func() { f.listenerClosed(l) })
	cancel()
	ev := forwardEvent{Op: "listen", Dir: "remote", Kind: l.kind, Addr: f.listenerAddr(l, bound)}
	if err != nil {
		ev.Result = refusalCode(err)
		f.record(ev)
		return false, nil
	}
	l.id, l.port = id, uint32(bound)
	if network == launcher.FwdTCP && port == 0 {
		// Cancelled by the bound port, which the reply told the client.
		l.keys = []string{tcpListenerKey(l.addr, l.port)}
	}
	if hook := beforeListenerRegistration.Load(); hook != nil {
		(*hook)(f, l)
	}
	c.mu.Lock()
	// A resume may have disallowed remote forwarding since the request was
	// checked.
	denied := !f.allowed(true)
	full = c.ended || f.countListeners() >= maxRemoteListeners
	if !full && !denied {
		for _, k := range l.keys {
			f.listeners[k] = l
		}
	}
	c.mu.Unlock()
	if full || denied {
		client.CloseListener(id)
		ev.Result = launcher.FwdCodeName(launcher.FwdCodeLimit)
		if denied {
			ev.Result = launcher.FwdCodeName(launcher.FwdCodePermissionDenied)
		}
		f.record(ev)
		return false, nil
	}
	ev.Result = "ok"
	f.record(ev)
	if network == launcher.FwdTCP && port == 0 {
		return true, ssh.Marshal(struct{ Port uint32 }{l.port})
	}
	return true, nil
}

// countListeners counts distinct listeners; c.mu held.
func (f *forwarder) countListeners() int {
	seen := map[*remoteListener]struct{}{}
	for _, l := range f.listeners {
		seen[l] = struct{}{}
	}
	return len(seen)
}

func (f *forwarder) listenerAddr(l *remoteListener, bound uint16) string {
	if l.kind == "unix" {
		return l.path
	}
	host := "127.0.0.1"
	if l.addr == "::1" {
		host = "::1"
	}
	return net.JoinHostPort(host, strconv.Itoa(int(bound)))
}

// forget removes l from the listener table; false when it was not there.
func (f *forwarder) forget(l *remoteListener) bool {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	found := false
	for _, k := range l.keys {
		if f.listeners[k] == l {
			delete(f.listeners, k)
			found = true
		}
	}
	return found
}

// cancelListen serves a cancel request: the listener named by the bind
// address and port (the bound one for a port 0 request) or by the path
// closes.
func (f *forwarder) cancelListen(r *ssh.Request) bool {
	var key string
	if r.Type == reqCancelTCPIPForward {
		var p struct {
			Addr string
			Port uint32
		}
		if ssh.Unmarshal(r.Payload, &p) != nil {
			return false
		}
		key = tcpListenerKey(p.Addr, p.Port)
	} else {
		var p struct{ Path string }
		if ssh.Unmarshal(r.Payload, &p) != nil {
			return false
		}
		key = unixListenerKey(p.Path)
	}
	f.c.mu.Lock()
	l, client := f.listeners[key], f.client
	f.c.mu.Unlock()
	if l == nil || !f.forget(l) {
		return false
	}
	client.CloseListener(l.id)
	f.record(forwardEvent{Op: "unlisten", Dir: "remote", Kind: l.kind, Addr: f.listenerAddr(l, uint16(l.port))})
	return true
}

// listenerClosed records a listener the helper ended (its own failure, or
// the helper's end).
func (f *forwarder) listenerClosed(l *remoteListener) {
	// Runs on the client's reader, which must not wait for listen to settle.
	f.wg.Go(func() {
		<-l.ready
		if f.forget(l) {
			f.record(forwardEvent{Op: "unlisten", Dir: "remote", Kind: l.kind, Addr: f.listenerAddr(l, uint16(l.port))})
		}
	})
}

// accepted runs on the helper client's reader for each connection a remote
// listener accepted: it takes a slot and opens the forwarded channel on its
// own goroutine. The watch goroutine, which waits for the reader's end, keeps
// the connection's WaitGroup above zero meanwhile.
func (f *forwarder) accepted(l *remoteListener, a launcher.Accepted) {
	if !f.reserve() {
		_ = a.Conn.Close()
		return
	}
	f.wg.Go(func() {
		defer f.release()
		<-l.ready
		f.c.mu.Lock()
		live := len(l.keys) > 0 && f.listeners[l.keys[0]] == l
		f.c.mu.Unlock()
		if !live {
			_ = a.Conn.Close()
			return
		}
		var chanType string
		var payload []byte
		origin := ""
		if l.kind == "unix" {
			chanType = chanForwardedStreamLocal
			payload = ssh.Marshal(struct{ Path, Reserved string }{l.path, ""})
		} else {
			chanType = chanForwardedTCPIP
			origin = net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
			payload = ssh.Marshal(struct {
				Addr     string
				Port     uint32
				OrigAddr string
				OrigPort uint32
			}{l.addr, l.port, a.Host, uint32(a.Port)})
		}
		addr := f.listenerAddr(l, uint16(l.port))
		ev := forwardEvent{Op: "open", Dir: "remote", Kind: l.kind, Addr: addr, Origin: origin}
		ch, reqs, err := f.sc.OpenChannel(chanType, payload)
		if err != nil {
			_ = a.Conn.Close()
			ev.Result = "channel_refused"
			f.record(ev)
			return
		}
		f.wg.Go(func() { ssh.DiscardRequests(reqs) })
		ev.Result = "ok"
		f.record(ev)
		f.relayAndRecord(ch, a.Conn, forwardEvent{Op: "close", Dir: "remote", Kind: l.kind, Addr: addr, Origin: origin})
	})
}

// activityWriter counts every forwarded write as connection activity for
// the idle timer.
type activityWriter struct {
	w io.Writer
	c *conn
}

func (a activityWriter) Write(p []byte) (int, error) {
	a.c.active()
	return a.w.Write(p)
}

// relay copies between an SSH forward channel and its connection until both
// directions ended (each end's EOF half-closes the other) or either fails,
// then closes both. in counts bytes from the client toward the target, out
// bytes back.
func (c *conn) relay(ch ssh.Channel, fc launcher.ForwardConn) (in, out int64) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		var err error
		in, err = io.Copy(activityWriter{fc, c}, ch)
		if err != nil {
			_ = fc.Close()
			_ = ch.Close()
			return
		}
		_ = fc.CloseWrite()
	}()
	var err error
	out, err = io.Copy(activityWriter{ch, c}, fc)
	if err != nil {
		_ = ch.Close()
		_ = fc.Close()
	} else {
		_ = ch.CloseWrite()
	}
	<-done
	_ = ch.Close()
	_ = fc.Close()
	return in, out
}
