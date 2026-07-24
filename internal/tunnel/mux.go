package tunnel

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// muxServer answers the data streams an edge opens on the multiplexed
// connection. Each stream stands in for one inbound visitor connection: the
// request body carries what the visitor sent, the response body carries what
// the local service replies.
//
// The stream is treated as opaque bytes, exactly as a dialed-back socket was.
// That keeps one mechanism serving HTTP, TCP and TLS tunnels alike, keeps the
// local service's bytes untouched on the way through, and keeps the agent from
// having to understand any protocol it is carrying.
type muxServer struct {
	// dialLocal opens a connection to the tunnelled service. Injected so the
	// stream path can be exercised without a real listener.
	dialLocal func() (net.Conn, error)

	// tracker publishes stream lifecycle into the tunnel's live connection view.
	// Nil disables tracking, which is what the tests use.
	tracker muxTracker

	// Tunnel-wide totals, updated as bytes move rather than at close so a
	// long-lived stream is not invisible until it ends.
	totalIn  *atomic.Int64
	totalOut *atomic.Int64

	// newInspector returns an inspector for the stream, nil when uninspected.
	newInspector func() *httpInspector
}

// muxTracker mirrors what proxyData does for a dialed-back connection, so the
// live view and its counters look identical whichever transport carried the
// traffic.
type muxTracker interface {
	Begin(remote string) *activeConn
	End(ac *activeConn, err error)
}

func (s *muxServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	remote := r.Header.Get(headerVisitorAddr)

	local, err := s.dialLocal()
	if err != nil {
		// A refused stream is reported by status so the edge can surface a
		// gateway error to the visitor instead of leaving it waiting.
		http.Error(w, "local service unreachable", http.StatusBadGateway)
		return
	}
	defer local.Close()

	// Headers go out before a single byte of the request has been read. The edge
	// blocks on them, so deferring them until the visitor finished talking would
	// deadlock any exchange where the response precedes the request's end, which
	// is most of them.
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var ac *activeConn
	if s.tracker != nil {
		ac = s.tracker.Begin(remote)
	}

	inCounters := s.counters(ac, true)
	outCounters := s.counters(ac, false)

	// http tunnels: the scanner reads a copy off the read side; forwarding is
	// untouched.
	reqSrc, respSrc := io.Reader(r.Body), io.Reader(local)
	if s.newInspector != nil {
		if insp := s.newInspector(); insp != nil {
			reqSrc = insp.wrapRequest(r.Body)
			respSrc = insp.wrapResponse(local)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		copyWithCounters(local, reqSrc, inCounters...)
		// Propagate the visitor's half-close so a local service waiting on EOF
		// (anything request/response shaped) sees it and replies.
		halfCloseOrClose(local)
	}()

	copyWithCounters(&flushWriter{w: w, f: flusher}, respSrc, outCounters...)
	wg.Wait()

	if s.tracker != nil {
		s.tracker.End(ac, nil)
	}
}

// counters returns the atomics a copy in one direction should feed: the
// per-stream counter when the stream is tracked, plus the tunnel total.
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

// ignoreClosed drops the errors that simply mean the peer finished, so a normal
// teardown is not reported as a failure.
func ignoreClosed(err error) error {
	if err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, http.ErrBodyReadAfterClose) {
		return nil
	}
	return err
}

// headerVisitorAddr carries the visitor's address, which the dial-back path
// delivered in the NewConnection frame. It is the peer address only; no visitor
// payload is ever inspected or logged here.
const headerVisitorAddr = "Localport-Visitor-Addr"
