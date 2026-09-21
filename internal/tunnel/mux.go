package tunnel

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
)

// muxServer serves the streams the edge opens on the multiplexed connection.
// Each stream is one visitor connection. The request body carries visitor
// bytes and the response body carries local service bytes. Streams are opaque,
// so HTTP, TCP and TLS tunnels share this path.
type muxServer struct {
	// dialTarget connects to the local target or returns the status to answer
	// with. Tests replace it.
	dialTarget func(port uint16) (net.Conn, int, error)

	// device marks a fleet device, whose streams name a port.
	device bool

	// defaultProto is the tunnel protocol for streams that name none.
	defaultProto string

	// tracker reports streams to the live connection view. Nil disables it.
	tracker muxTracker

	// Tunnel totals, updated as bytes move so long-lived streams are counted.
	totalIn  *atomic.Int64
	totalOut *atomic.Int64

	// newInspector returns an inspector for the stream's protocol and port, or
	// nil.
	newInspector func(protocol string, port uint16) *httpInspector
}

// muxTracker reports mux streams the same way proxyData reports dial-back
// connections.
type muxTracker interface {
	// local is the dialed target. Closing it cuts the stream when its port
	// closes.
	Begin(remote string, target connTarget, local net.Conn) *activeConn
	End(ac *activeConn, err error)
}

func (s *muxServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Header values are displayed and logged, so strip control characters.
	remote := sanitizeDisplay(r.Header.Get(headerVisitorAddr))
	target := connTarget{
		protocol: sanitizeDisplay(r.Header.Get(headerTargetProtocol)),
		consumer: sanitizeDisplay(r.Header.Get(headerConsumer)),
	}
	if s.device {
		port, err := strconv.ParseUint(r.Header.Get(headerTargetPort), 10, 16)
		if err != nil {
			http.Error(w, "no port requested", http.StatusForbidden)
			return
		}
		target.port = uint16(port)
	}
	if target.protocol == "" {
		target.protocol = s.defaultProto
	}

	// dialTarget refuses unserved ports before dialing and returns the status
	// the edge relays to the consumer.
	local, status, err := s.dialTarget(target.port)
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer local.Close()

	// Send headers before reading the request. The edge waits for them, and
	// most protocols reply before the request stream ends.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var ac *activeConn
	if s.tracker != nil {
		ac = s.tracker.Begin(remote, target, local)
	}

	inCounters := s.counters(ac, true)
	outCounters := s.counters(ac, false)

	// On http tunnels the scanner reads a copy of the traffic.
	reqSrc, respSrc := io.Reader(r.Body), io.Reader(local)
	if s.newInspector != nil {
		if insp := s.newInspector(target.protocol, target.port); insp != nil {
			reqSrc = insp.wrapRequest(r.Body)
			respSrc = insp.wrapResponse(local)
		}
	}

	var wg sync.WaitGroup
	var reqErr error
	wg.Go(func() {
		reqErr = copyWithCounters(local, reqSrc, inCounters...)
		// Forward the visitor half-close so a service waiting for EOF replies.
		halfCloseOrClose(local)
	})

	respErr := copyWithCounters(&flushWriter{w: w, f: flusher}, respSrc, outCounters...)
	wg.Wait()

	if s.tracker != nil {
		s.tracker.End(ac, firstCopyError(respErr, reqErr))
	}
}

// counters returns the byte counters for one direction, the tunnel total and
// the stream counter when tracked.
func (s *muxServer) counters(ac *activeConn, inbound bool) []*atomic.Int64 {
	var out []*atomic.Int64
	if ac != nil {
		if inbound {
			out = append(out, &ac.bytesIn)
		} else {
			out = append(out, &ac.bytesOut)
		}
	}
	if inbound && s.totalIn != nil {
		out = append(out, s.totalIn)
	}
	if !inbound && s.totalOut != nil {
		out = append(out, s.totalOut)
	}
	return out
}

// flushWriter pushes each chunk out as it is produced. Without it the HTTP/2
// stack accumulates writes, which stalls anything the local service streams:
// server-sent events, long polls, an interactive TCP session.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

// Stream headers set by the edge. They carry the NewConnection fields of the
// dial-back path. Consumer bytes travel in the body and cannot set them.
const (
	headerVisitorAddr    = "Localport-Visitor-Addr"
	headerTargetPort     = "Localport-Target-Port"
	headerTargetProtocol = "Localport-Target-Protocol"
	headerConsumer       = "Localport-Consumer"
)
