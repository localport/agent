//go:build linux || darwin

package session

import (
	"encoding/binary"
	"testing"
)

// clipCaps runs the cliprdr capability exchange: both sides' capabilities
// reach the other with the file and lock flags cleared.
func clipCaps(r *rdpRun) {
	r.t.Helper()
	if r.clipReady {
		return
	}
	r.clipReady = true
	r.send(rdpServer, rdpPDU(r.t, "s.caps"))
	r.expect(rdpClient, rdpPDU(r.t, "s.caps_cleared"))
	r.pass(rdpServer, rdpPDU(r.t, "s.monitor_ready"))
	r.send(rdpClient, rdpPDU(r.t, "c.caps"))
	r.expect(rdpServer, rdpPDU(r.t, "c.caps_cleared"))
}

// copyListed forwards the server's text formats to the client.
func copyListed(r *rdpRun) {
	r.t.Helper()
	clipCaps(r)
	r.send(rdpServer, rdpPDU(r.t, "s.list_mixed_long"))
	r.expect(rdpClient, rdpPDU(r.t, "s.list_text_long"))
	r.pass(rdpClient, rdpPDU(r.t, "c.list_ok"))
}

// copyRequested leaves a client request for the server's text outstanding.
func copyRequested(r *rdpRun) {
	r.t.Helper()
	copyListed(r)
	r.pass(rdpClient, rdpPDU(r.t, "c.req_unicode"))
}

// pasteRequested leaves a server request for the client's text outstanding.
func pasteRequested(r *rdpRun) {
	r.t.Helper()
	clipCaps(r)
	r.send(rdpClient, rdpPDU(r.t, "c.list_mixed_long"))
	r.expect(rdpServer, rdpPDU(r.t, "c.list_text_long"))
	r.pass(rdpServer, rdpPDU(r.t, "s.list_ok"))
	r.pass(rdpServer, rdpPDU(r.t, "s.req_unicode"))
}

// Each direction forwards text both ways only when its grant allows it; a
// refused list is answered by the agent and never reaches the receiver.
func TestRDPClipboardDirections(t *testing.T) {
	for name, access := range map[string]clipboardAccess{
		"both": allClipboard, "copy": {Copy: true}, "paste": {Paste: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, access)
			r.connect("base")
			clipCaps(r)
			if access.Copy {
				copyRequested(r)
				r.pass(rdpServer, rdpPDU(t, "s.resp_text"))
			} else {
				r.send(rdpServer, rdpPDU(t, "s.list_mixed_long"))
				r.expect(rdpServer, rdpPDU(t, "c.list_ok"))
				r.marker(rdpServer)
				r.send(rdpClient, rdpPDU(t, "c.req_unicode"))
				r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
			}
			if access.Paste {
				pasteRequested(r)
				r.pass(rdpClient, rdpPDU(t, "c.resp_text"))
			} else {
				r.send(rdpClient, rdpPDU(t, "c.list_mixed_long"))
				r.expect(rdpClient, rdpPDU(t, "s.list_ok"))
				r.marker(rdpClient)
				r.send(rdpServer, rdpPDU(t, "s.req_unicode"))
				r.expect(rdpServer, rdpPDU(t, "c.resp_fail"))
			}
			r.marker(rdpClient)
			r.marker(rdpServer)
		})
	}
}

// Short format names: text entries kept, the rest stripped, flags kept.
func TestRDPClipboardShortNames(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	r.send(rdpServer, rdpPDU(t, "s.caps_short"))
	r.expect(rdpClient, rdpPDU(t, "s.caps_short"))
	r.send(rdpClient, rdpPDU(t, "c.caps_short"))
	r.expect(rdpServer, rdpPDU(t, "c.caps_short"))
	r.send(rdpServer, rdpPDU(t, "s.list_mixed_short"))
	r.expect(rdpClient, rdpPDU(t, "s.list_text_short"))
}

// A request for a format the agent did not forward is answered
// RESPONSE_FAIL by the agent; the target never sees it.
func TestRDPClipboardUnlistedRequest(t *testing.T) {
	for _, req := range []string{"c.req_html", "c.req_dib"} {
		t.Run(req, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			copyListed(r)
			r.send(rdpClient, rdpPDU(t, req))
			r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
			r.marker(rdpClient)
		})
	}
}

// Requests are answered in order: the agent's RESPONSE_FAIL for a refused
// request waits behind the answer to the request before it; a 65th
// outstanding request ends the connection.
func TestRDPClipboardRequestQueue(t *testing.T) {
	t.Run("order", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyRequested(r)
		r.send(rdpClient, rdpPDU(t, "c.req_html"))
		r.pass(rdpClient, rdpPDU(t, "c.req_text"))
		r.marker(rdpClient)
		r.pass(rdpServer, rdpPDU(t, "s.resp_text"))
		r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
		r.pass(rdpServer, rdpPDU(t, "s.resp_text"))
		r.marker(rdpServer)
	})
	t.Run("bound", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyListed(r)
		for range rdpMaxClipQueue {
			r.pass(rdpClient, rdpPDU(t, "c.req_unicode"))
		}
		r.send(rdpClient, rdpPDU(t, "c.req_unicode"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("answer without a request", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyListed(r)
		r.send(rdpServer, rdpPDU(t, "s.resp_text"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
}

// A list the agent refuses or empties replaces the receiver's view with an
// empty list, whose answer the agent absorbs; requests for the old formats
// then fail. A resume that narrows a direction does the same.
func TestRDPClipboardReceiverView(t *testing.T) {
	t.Run("emptied list", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyListed(r)
		r.send(rdpServer, rdpPDU(t, "s.list_image_long"))
		r.expect(rdpServer, rdpPDU(t, "c.list_ok"))
		r.expect(rdpClient, rdpPDU(t, "s.list_empty_long"))
		r.send(rdpClient, rdpPDU(t, "c.list_ok"))
		r.marker(rdpClient)
		r.send(rdpClient, rdpPDU(t, "c.req_unicode"))
		r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
	})
	t.Run("narrowed by a resume", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyListed(r)
		r.f.c.adm.Store(&connAdmission{admission: &admission{Kind: "rdp", Clipboard: clipboardAccess{Paste: true}}})
		r.send(rdpClient, rdpPDU(t, "c.req_unicode"))
		r.expect(rdpClient, rdpPDU(t, "s.list_empty_long"))
		r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
		r.send(rdpClient, rdpPDU(t, "c.list_ok"))
		r.marker(rdpClient)
	})
	t.Run("narrowed while a request is outstanding", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyRequested(r)
		r.f.c.adm.Store(&connAdmission{admission: &admission{Kind: "rdp", Clipboard: clipboardAccess{Paste: true}}})
		r.send(rdpServer, rdpPDU(t, "s.resp_text"))
		r.expect(rdpClient, rdpPDU(t, "s.list_empty_long"))
		r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
	})
}

// A response over rdpMaxClipText is discarded, not buffered, and the
// requester gets RESPONSE_FAIL; one within the bound passes.
func TestRDPClipboardResponseBound(t *testing.T) {
	for name, tc := range map[string]struct {
		size int
		fail bool
	}{
		"at the bound":              {size: rdpMaxClipText},
		"over the bound":            {size: rdpMaxClipText + 1, fail: true},
		"past the reassembly bound": {size: rdpMaxClipPDU, fail: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			copyRequested(r)
			resp := r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbFormatDataResponse, cbResponseOK, make([]byte, tc.size)), 0)
			r.send(rdpServer, resp)
			if tc.fail {
				r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
			} else {
				r.expect(rdpClient, resp)
			}
			r.marker(rdpServer)
		})
	}
}

// File and lock PDUs never cross: a file contents request is answered
// RESPONSE_FAIL with its stream id, the rest dropped.
func TestRDPClipboardFilePDUs(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	clipCaps(r)
	r.send(rdpClient, rdpPDU(t, "c.temp_dir"))
	r.send(rdpClient, rdpPDU(t, "c.lock"))
	r.send(rdpClient, rdpPDU(t, "c.unlock"))
	r.send(rdpClient, rdpPDU(t, "c.filecontents_data"))
	r.marker(rdpClient)
	r.send(rdpClient, rdpPDU(t, "c.filecontents_req"))
	r.expect(rdpClient, rdpPDU(t, "s.filecontents_fail"))
	r.send(rdpServer, rdpPDU(t, "s.filecontents_req"))
	r.expect(rdpServer, rdpPDU(t, "c.filecontents_fail"))
	r.send(rdpServer, rdpPDU(t, "s.lock"))
	r.marker(rdpServer)
}

// Malformed and misdirected cliprdr PDUs end the connection.
func TestRDPClipboardRefusals(t *testing.T) {
	lengthPast := func(r *rdpRun) []byte {
		pdu := cliprdrPDU(cbFormatDataRequest, 0, []byte{13, 0, 0, 0})
		binary.LittleEndian.PutUint32(pdu[4:], 5)
		return r.svc(rdpClient, rdpCliprdr, pdu, 0)
	}
	for name, tc := range map[string]struct {
		from rdpSide
		pdu  func(*rdpRun) []byte
	}{
		"dataLen past the message":      {rdpClient, lengthPast},
		"monitor ready from the client": {rdpClient, func(r *rdpRun) []byte { return rdpPDU(r.t, "c.monitor_ready") }},
		"unknown type":                  {rdpClient, func(r *rdpRun) []byte { return r.svc(rdpClient, rdpCliprdr, cliprdrPDU(0x20, 0, nil), 0) }},
		"list answer without a list":    {rdpServer, func(r *rdpRun) []byte { return rdpPDU(r.t, "s.list_ok") }},
		"truncated long name": {rdpServer, func(r *rdpRun) []byte {
			return r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbFormatList, 0, []byte{13, 0, 0, 0, 'a', 0}), 0)
		}},
		"ASCII names with long names": {rdpServer, func(r *rdpRun) []byte {
			return r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbFormatList, cbASCIINames, nil), 0)
		}},
		"request flags": {rdpClient, func(r *rdpRun) []byte {
			return r.svc(rdpClient, rdpCliprdr, cliprdrPDU(cbFormatDataRequest, cbResponseOK, []byte{13, 0, 0, 0}), 0)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			clipCaps(r)
			r.send(tc.from, tc.pdu(r))
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}
