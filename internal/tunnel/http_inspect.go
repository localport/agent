package tunnel

import (
	"bytes"
	"io"
	"strconv"
	"sync"
	"time"
)

// HTTP request inspection for the live TUI view, display only.
//
// For an http tunnel the forwarded bytes are a plaintext HTTP/1.x exchange, so
// method, path and status are read off a copy inline as they forward. Bodies are
// skipped by their framing (Content-Length or chunked), never stored. No
// goroutine, no buffer past one message's headers. A scanner fault is recovered;
// forwarding never waits on it. tcp/tls/mtls are opaque and not inspected.

// Beyond these caps the stream is not shaped like we expect, so the scanner stops
// on that connection rather than grow unbounded.
const (
	maxHeaderBytes = 16 << 10
	maxLineBytes   = 256 // one chunk-size or trailer line
)

// maxPending caps requests awaiting a response. Ordered, non-pipelined traffic
// keeps this at one or two; growth means responses stopped matching (a dead
// response scanner on a live connection), so the oldest is dropped.
const maxPending = 256

var headerEnd = []byte("\r\n\r\n")

// pendingRequest is a request whose response has not been seen yet. Requests and
// responses are matched in arrival order, which is correct because a connection
// carries them in order and the edge does not pipeline.
type pendingRequest struct {
	method string
	path   string
	at     time.Time
}

type httpInspector struct {
	emit func(RequestInfo)

	mu      sync.Mutex
	pending []pendingRequest

	reqDir  dirScanner
	respDir dirScanner
}

func newHTTPInspector(emit func(RequestInfo)) *httpInspector {
	return &httpInspector{emit: emit}
}

// wrapRequest and wrapResponse wrap the read side of each direction. The bytes
// are forwarded unchanged; a copy is fed to the scanner under recover so a
// scanner fault cannot break forwarding.
func (in *httpInspector) wrapRequest(src io.Reader) io.Reader {
	return &scanReader{src: src, feed: in.feedRequest}
}

func (in *httpInspector) wrapResponse(src io.Reader) io.Reader {
	return &scanReader{src: src, feed: in.feedResponse}
}

// scanReader forwards src unchanged and feeds a copy of each read to a scanner.
type scanReader struct {
	src  io.Reader
	feed func([]byte)
}

func (s *scanReader) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	if n > 0 {
		s.safeFeed(p[:n])
	}
	return n, err
}

func (s *scanReader) safeFeed(b []byte) {
	// A scanner fault is a display bug, never a reason to break the tunnel.
	defer func() { _ = recover() }()
	s.feed(b)
}

func (in *httpInspector) feedRequest(b []byte) {
	in.reqDir.feed(b, func(hdr []byte) bodyPlan {
		method, path, ok := parseRequestLine(hdr)
		if !ok {
			return bodyPlan{mode: bodyDead}
		}
		in.mu.Lock()
		if len(in.pending) >= maxPending {
			in.pending = in.pending[1:]
		}
		in.pending = append(in.pending, pendingRequest{method: method, path: path, at: time.Now()})
		in.mu.Unlock()
		return requestBodyPlan(hdr)
	})
}

func (in *httpInspector) feedResponse(b []byte) {
	in.respDir.feed(b, func(hdr []byte) bodyPlan {
		status, ok := parseStatusLine(hdr)
		if !ok {
			return bodyPlan{mode: bodyDead}
		}
		// 1xx (other than 101) is interim: no request is answered and there is
		// no body. Wait for the final response.
		if status >= 100 && status < 200 && status != 101 {
			return bodyPlan{mode: bodyNone}
		}

		in.mu.Lock()
		var pr pendingRequest
		have := len(in.pending) > 0
		if have {
			pr = in.pending[0]
			in.pending = in.pending[1:]
		}
		in.mu.Unlock()

		if have {
			// emit runs on the forwarding goroutine, so its sink must not block.
			// The TUI's is a coalescing, non-blocking signal.
			in.emit(RequestInfo{
				Method:    pr.method,
				Path:      pr.path,
				Status:    status,
				Duration:  time.Since(pr.at),
				StartedAt: pr.at,
			})
		}

		return responseBodyPlan(hdr, status, have, pr.method)
	})
}

// bodyMode is how the scanner advances past a message body to reach the next
// message on the same connection.
type bodyMode int

const (
	bodyNone    bodyMode = iota // no body, or done with the current one: read headers next
	bodyLen                     // skip a fixed number of bytes
	bodyChunked                 // skip a chunked body
	bodyDead                    // stop scanning this connection
)

type bodyPlan struct {
	mode   bodyMode
	remain int64 // for bodyLen
}

// dirScanner walks one direction of a connection: header block, then body skip,
// repeating for each message. It keeps only the current header block in memory.
type dirScanner struct {
	hdr    []byte
	mode   bodyMode // bodyNone means "in the header phase"
	remain int64
	chunk  chunkSkipper
	dead   bool
}

func (d *dirScanner) feed(data []byte, onHeaders func(hdr []byte) bodyPlan) {
	for len(data) > 0 && !d.dead {
		switch d.mode {
		case bodyNone:
			consumed, complete := appendUntilHeadersEnd(&d.hdr, data)
			data = data[consumed:]
			if !complete {
				if len(d.hdr) > maxHeaderBytes {
					d.dead = true
				}
				return
			}
			plan := onHeaders(d.hdr)
			d.hdr = d.hdr[:0]
			switch plan.mode {
			case bodyDead:
				d.dead = true
				return
			case bodyLen:
				if plan.remain > 0 {
					d.mode = bodyLen
					d.remain = plan.remain
				}
			case bodyChunked:
				d.mode = bodyChunked
				d.chunk = chunkSkipper{}
			}
		case bodyLen:
			take := int64(len(data))
			if d.remain < take {
				take = d.remain
			}
			d.remain -= take
			data = data[take:]
			if d.remain == 0 {
				d.mode = bodyNone
			}
		case bodyChunked:
			used, done := d.chunk.consume(data)
			data = data[used:]
			if d.chunk.dead {
				d.dead = true
				return
			}
			if done {
				d.mode = bodyNone
			}
		}
	}
}

// appendUntilHeadersEnd appends data to hdr and looks for the end of the header
// block. It returns how many bytes of data belong to the header block (the rest
// is the body, left for the caller) and whether the block is complete. On
// completion hdr is trimmed to exactly the header block.
func appendUntilHeadersEnd(hdr *[]byte, data []byte) (consumed int, complete bool) {
	before := len(*hdr)
	*hdr = append(*hdr, data...)
	idx := bytes.Index(*hdr, headerEnd)
	if idx < 0 {
		return len(data), false
	}
	end := idx + len(headerEnd)
	*hdr = (*hdr)[:end]
	return end - before, true
}

func requestBodyPlan(hdr []byte) bodyPlan {
	cl, hasCL, chunked := scanFraming(hdr)
	switch {
	case chunked:
		return bodyPlan{mode: bodyChunked}
	case hasCL && cl > 0:
		return bodyPlan{mode: bodyLen, remain: cl}
	default:
		return bodyPlan{mode: bodyNone}
	}
}

// responseBodyPlan decides how to skip a response body. Body presence follows
// RFC 7230: 204, 304 and any response to HEAD carry none; 101 upgrades leave
// HTTP entirely; a final response without Content-Length or chunked runs to the
// connection close, which is the last message on it.
func responseBodyPlan(hdr []byte, status int, haveReq bool, method string) bodyPlan {
	if status == 101 {
		return bodyPlan{mode: bodyDead}
	}
	if status == 204 || status == 304 || (haveReq && method == "HEAD") {
		return bodyPlan{mode: bodyNone}
	}
	cl, hasCL, chunked := scanFraming(hdr)
	switch {
	case chunked:
		return bodyPlan{mode: bodyChunked}
	case hasCL:
		if cl > 0 {
			return bodyPlan{mode: bodyLen, remain: cl}
		}
		return bodyPlan{mode: bodyNone}
	default:
		return bodyPlan{mode: bodyDead}
	}
}

// parseRequestLine reads "METHOD target HTTP/x.y" from the head of hdr. The
// target's query string is dropped so a token in a query never reaches the view.
func parseRequestLine(hdr []byte) (method, path string, ok bool) {
	line := firstLine(hdr)
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return "", "", false
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return "", "", false
	}
	target := rest[:sp2]
	if !bytes.HasPrefix(rest[sp2+1:], []byte("HTTP/")) {
		return "", "", false
	}
	if q := bytes.IndexByte(target, '?'); q >= 0 {
		target = target[:q]
	}
	return string(line[:sp1]), string(target), true
}

func parseStatusLine(hdr []byte) (status int, ok bool) {
	line := firstLine(hdr)
	if !bytes.HasPrefix(line, []byte("HTTP/")) {
		return 0, false
	}
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return 0, false
	}
	rest := line[sp1+1:]
	code := rest
	if sp2 := bytes.IndexByte(rest, ' '); sp2 >= 0 {
		code = rest[:sp2]
	}
	n, err := strconv.Atoi(string(code))
	if err != nil || n < 100 || n > 599 {
		return 0, false
	}
	return n, true
}

func firstLine(hdr []byte) []byte {
	if i := bytes.Index(hdr, []byte("\r\n")); i >= 0 {
		return hdr[:i]
	}
	return hdr
}

// scanFraming reads the body-framing headers. Transfer-Encoding: chunked wins
// over Content-Length per the spec, so it is reported and the caller prefers it.
func scanFraming(hdr []byte) (contentLen int64, hasCL, chunked bool) {
	if i := bytes.Index(hdr, []byte("\r\n")); i >= 0 { // past the start line
		hdr = hdr[i+2:]
	}
	for len(hdr) > 0 {
		var line []byte
		if i := bytes.Index(hdr, []byte("\r\n")); i >= 0 {
			line, hdr = hdr[:i], hdr[i+2:]
		} else {
			line, hdr = hdr, nil
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := bytes.TrimSpace(line[:colon])
		val := bytes.TrimSpace(line[colon+1:])
		switch {
		case equalFold(key, "content-length"):
			if n, err := strconv.ParseInt(string(val), 10, 64); err == nil && n >= 0 {
				contentLen, hasCL = n, true
			}
		case equalFold(key, "transfer-encoding"):
			if bytes.Contains(bytes.ToLower(val), []byte("chunked")) {
				chunked = true
			}
		}
	}
	return contentLen, hasCL, chunked
}

func equalFold(b []byte, s string) bool {
	return bytes.EqualFold(b, []byte(s))
}

// chunkPhase tracks where the chunked-body skipper is within the framing.
type chunkPhase int

const (
	chunkSize    chunkPhase = iota // reading the "<hex>\r\n" size line
	chunkData                      // skipping chunk data bytes
	chunkDataEnd                   // consuming the "\r\n" after chunk data
	chunkTrailer                   // reading trailers until a blank line
)

// chunkSkipper advances past a chunked body without storing it. It parses only
// the size lines and trailers, both tiny, and counts down data bytes.
type chunkSkipper struct {
	phase  chunkPhase
	line   []byte
	remain int64
	dead   bool
}

// consume skips as much of data as belongs to the chunked body. It returns how
// many bytes it consumed and whether the body is complete (the rest of data is
// the next message).
func (c *chunkSkipper) consume(data []byte) (used int, done bool) {
	for used < len(data) {
		switch c.phase {
		case chunkSize:
			line, n, ready := c.readLine(data[used:])
			used += n
			if !ready {
				return used, false
			}
			size, ok := parseChunkSize(line)
			if !ok {
				c.dead = true
				return used, false
			}
			if size == 0 {
				c.phase = chunkTrailer
			} else {
				c.remain = size
				c.phase = chunkData
			}
		case chunkData:
			take := int64(len(data) - used)
			if c.remain < take {
				take = c.remain
			}
			c.remain -= take
			used += int(take)
			if c.remain == 0 {
				c.phase = chunkDataEnd
			}
		case chunkDataEnd:
			_, n, ready := c.readLine(data[used:])
			used += n
			if !ready {
				return used, false
			}
			c.phase = chunkSize
		case chunkTrailer:
			line, n, ready := c.readLine(data[used:])
			used += n
			if !ready {
				return used, false
			}
			if len(line) == 0 {
				return used, true // blank line ends the trailers and the body
			}
			// A trailer header; keep reading until the blank line.
		}
	}
	return used, false
}

// readLine accumulates bytes up to and including the next LF, returning the line
// without its trailing CRLF. ready is false when more input is needed. It caps
// the accumulator so a missing terminator cannot grow it without bound.
func (c *chunkSkipper) readLine(data []byte) (line []byte, used int, ready bool) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		c.line = append(c.line, data...)
		if len(c.line) > maxLineBytes {
			c.dead = true
		}
		return nil, len(data), false
	}
	c.line = append(c.line, data[:nl+1]...)
	full := c.line
	c.line = c.line[:0]
	return trimCRLF(full), nl + 1, true
}

func trimCRLF(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	b = bytes.TrimSuffix(b, []byte("\r"))
	return b
}

// parseChunkSize reads the hex size at the head of a chunk-size line, ignoring
// any chunk extension after a semicolon.
func parseChunkSize(line []byte) (int64, bool) {
	if i := bytes.IndexByte(line, ';'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(string(line), 16, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
