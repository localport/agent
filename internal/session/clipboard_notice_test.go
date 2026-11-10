//go:build linux || darwin

package session

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// clipboardLog records the clipboard decisions a connection reports.
type clipboardLog struct {
	mu        sync.Mutex
	decisions []ClipboardDecision
}

// reportTo makes s report its clipboard decisions to l. Set before the
// filter runs.
func (l *clipboardLog) reportTo(s *Server) {
	s.cfg.OnClipboard = func(d ClipboardDecision) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.decisions = append(l.decisions, d)
	}
}

// clipDecision is a decision without its session and time.
type clipDecision struct {
	kind, direction, outcome string
	bytes                    int64
}

func (l *clipboardLog) take() []clipDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []clipDecision
	for _, d := range l.decisions {
		out = append(out, clipDecision{d.Kind, d.Direction, d.Outcome, d.Bytes})
	}
	l.decisions = nil
	return out
}

// await takes the decisions once n are recorded, failing after 3 s.
func (l *clipboardLog) await(t *testing.T, n int) []clipDecision {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		l.mu.Lock()
		got := len(l.decisions)
		l.mu.Unlock()
		if got >= n {
			return l.take()
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d decisions reported, want %d", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func (l *clipboardLog) want(t *testing.T, want ...clipDecision) {
	t.Helper()
	if got := l.take(); !slices.Equal(got, want) {
		t.Fatalf("decisions %+v, want %+v", got, want)
	}
}

// Every VNC CutText is reported once with its direction, length and
// outcome, whatever the grant; the session id is the connection's stream's.
func TestRFBReportsEveryCutTextDecision(t *testing.T) {
	text := []byte("clip")
	for _, tc := range []struct {
		access     clipboardAccess
		copyResult string
		pasteRes   string
	}{
		{clipboardAccess{}, clipboardDeniedPolicy, clipboardDeniedPolicy},
		{clipboardAccess{Copy: true}, clipboardAllowed, clipboardDeniedPolicy},
		{clipboardAccess{Paste: true}, clipboardDeniedPolicy, clipboardAllowed},
		{clipboardAccess{Copy: true, Paste: true}, clipboardAllowed, clipboardAllowed},
	} {
		r := newFilterRun(tc.access, rfbV38, rfbSecNone,
			cutText(rfbClientCutText, 4, text), cutText(rfbServerCutText, 4, text))
		r.c.adm.Load().sessionID = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
		var log clipboardLog
		log.reportTo(r.c.s)
		wantClosed(t, r.serverMessages())
		wantClosed(t, r.clientMessages())
		log.mu.Lock()
		for _, d := range log.decisions {
			if d.SessionID != "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b" || d.At.IsZero() {
				t.Fatalf("decision %+v lacks its session or time", d)
			}
		}
		log.mu.Unlock()
		log.want(t, clipDecision{"vnc", clipboardCopy, tc.copyResult, 4}, clipDecision{"vnc", clipboardPaste, tc.pasteRes, 4})
	}
}

// A CutText past the bound is reported denied_size, at the bound allowed.
func TestRFBReportsTheCutTextBound(t *testing.T) {
	both := clipboardAccess{Copy: true, Paste: true}
	for _, tc := range []struct {
		n    int
		want string
	}{{rfbMaxCutText, clipboardAllowed}, {rfbMaxCutText + 1, clipboardDeniedSize}} {
		r := newFilterRun(both, rfbV38, rfbSecNone, nil, cutText(rfbServerCutText, int32(tc.n), fill(tc.n)))
		var log clipboardLog
		log.reportTo(r.c.s)
		wantClosed(t, r.serverMessages())
		log.want(t, clipDecision{"vnc", clipboardCopy, tc.want, int64(tc.n)})
	}
}

// reportingRDPRun is an rdpRun whose decisions go to log.
func reportingRDPRun(t *testing.T, access clipboardAccess) (*rdpRun, *clipboardLog) {
	log := &clipboardLog{}
	r := newRDPRun(t, rdpProtocolSSL, access, func(f *rdpFilter) { log.reportTo(f.c.s) })
	r.connect("base")
	return r, log
}

// An RDP Format Data Response is reported per direction: allowed when it
// passes, denied_policy when its direction is refused at the response.
func TestRDPReportsDataResponses(t *testing.T) {
	r, log := reportingRDPRun(t, allClipboard)
	copyRequested(r)
	resp := rdpPDU(t, "s.resp_text")
	r.pass(rdpServer, resp)
	pasteRequested(r)
	r.pass(rdpClient, rdpPDU(t, "c.resp_text"))
	got := log.take()
	if len(got) != 2 || got[0].direction != clipboardCopy || got[0].outcome != clipboardAllowed || got[0].bytes <= 0 ||
		got[1].direction != clipboardPaste || got[1].outcome != clipboardAllowed || got[1].bytes <= 0 || got[0].kind != "rdp" {
		t.Fatalf("decisions %+v, want an allowed copy then an allowed paste", got)
	}

	// The grant narrows between the request and the response.
	copyRequested(r)
	r.f.c.adm.Store(&connAdmission{admission: &admission{Kind: "rdp", Clipboard: clipboardAccess{Paste: true}}})
	r.send(rdpServer, resp)
	if got := log.await(t, 1); got[0].outcome != clipboardDeniedPolicy || got[0].direction != clipboardCopy {
		t.Fatalf("decisions %+v, want one copy denied_policy", got)
	}
}

// A request the agent refuses is reported: denied_policy for a refused
// direction, denied_format for a format the agent did not forward; the
// responder's own failure is not a decision.
func TestRDPReportsRefusedRequests(t *testing.T) {
	r, log := reportingRDPRun(t, allClipboard)
	copyListed(r)
	r.send(rdpClient, rdpPDU(t, "c.req_html"))
	r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
	log.want(t, clipDecision{"rdp", clipboardCopy, clipboardDeniedFormat, 0})

	r.pass(rdpClient, rdpPDU(t, "c.req_unicode"))
	r.pass(rdpServer, rdpPDU(t, "s.resp_fail"))
	log.want(t)

	r, log = reportingRDPRun(t, clipboardAccess{Paste: true})
	clipCaps(r)
	r.send(rdpServer, rdpPDU(t, "s.list_mixed_long"))
	r.expect(rdpServer, rdpPDU(t, "c.list_ok"))
	r.send(rdpClient, rdpPDU(t, "c.req_unicode"))
	r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
	log.want(t, clipDecision{"rdp", clipboardCopy, clipboardDeniedPolicy, 0})
}

// A response past the text bound, kept or discarded, is reported
// denied_size with its data length.
func TestRDPReportsTheResponseBound(t *testing.T) {
	for _, size := range []int{rdpMaxClipText, rdpMaxClipText + 1, rdpMaxClipPDU} {
		r, log := reportingRDPRun(t, allClipboard)
		copyRequested(r)
		resp := r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbFormatDataResponse, cbResponseOK, make([]byte, size)), 0)
		r.send(rdpServer, resp)
		want := clipboardDeniedSize
		if size <= rdpMaxClipText {
			want = clipboardAllowed
			r.expect(rdpClient, resp)
		} else {
			r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
		}
		r.marker(rdpServer)
		log.want(t, clipDecision{"rdp", clipboardCopy, want, int64(size)})
	}
}

// A file contents request is reported denied_format in the requester's
// direction.
func TestRDPReportsFileContentsRequests(t *testing.T) {
	r, log := reportingRDPRun(t, allClipboard)
	clipCaps(r)
	r.send(rdpClient, rdpPDU(t, "c.filecontents_req"))
	r.expect(rdpClient, rdpPDU(t, "s.filecontents_fail"))
	r.send(rdpServer, rdpPDU(t, "s.filecontents_req"))
	r.expect(rdpServer, rdpPDU(t, "c.filecontents_fail"))
	log.want(t, clipDecision{"rdp", clipboardCopy, clipboardDeniedFormat, 0}, clipDecision{"rdp", clipboardPaste, clipboardDeniedFormat, 0})
}
