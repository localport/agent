//go:build linux || darwin

package session

import (
	"encoding/binary"
	"testing"
)

// clipCaps runs the cliprdr capability exchange: both sides' capabilities
// reach the other with only the long format names flag kept.
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

// The agent's answer to a refused list waits behind the receiver's answer to
// the sender's earlier forwarded list.
func TestRDPClipboardListAnswerOrder(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	clipCaps(r)
	r.send(rdpServer, rdpPDU(t, "s.list_mixed_long"))
	r.expect(rdpClient, rdpPDU(t, "s.list_text_long"))
	r.send(rdpServer, rdpPDU(t, "s.list_image_long"))
	r.expect(rdpClient, rdpPDU(t, "s.list_empty_long"))
	r.marker(rdpServer)
	r.send(rdpClient, rdpPDU(t, "c.list_fail"))
	r.expect(rdpServer, rdpPDU(t, "c.list_fail"))
	r.expect(rdpServer, rdpPDU(t, "c.list_ok"))
	r.send(rdpClient, rdpPDU(t, "c.list_ok"))
	r.marker(rdpClient)
}

// A cliprdr message of no bytes is malformed, never read as a discarded
// response: the outstanding request stays outstanding.
func TestRDPClipboardEmptyMessage(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	copyRequested(r)
	r.send(rdpServer, r.svc(rdpServer, rdpCliprdr, nil, 0))
	r.wantEnd(CloseDesktopProtocolViolation)
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

// capsSet is one CLIPRDR_CAPS_SET of type typ carrying body.
func capsSet(typ uint16, body ...byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, typ)
	b = binary.LittleEndian.AppendUint16(b, uint16(4+len(body)))
	return append(b, body...)
}

// capsData is Clipboard Capabilities data holding sets.
func capsData(sets ...[]byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(sets)))
	b = append(b, 0, 0)
	for _, s := range sets {
		b = append(b, s...)
	}
	return b
}

// The filter sends on one general set it builds: other sets, trailing bytes
// of the general set and every flag but long format names are dropped.
func TestRDPClipboardCapsRebuilt(t *testing.T) {
	general := func(version, flags uint32, extra ...byte) []byte {
		b := binary.LittleEndian.AppendUint32(nil, version)
		b = binary.LittleEndian.AppendUint32(b, flags)
		return capsSet(cbCapsTypeGeneral, append(b, extra...)...)
	}
	want := capsData(general(cbCapsVersion2, cbUseLongFormatNames))
	for name, data := range map[string][]byte{
		"unknown set before":    capsData(capsSet(0x7f, 1, 2, 3, 4), general(cbCapsVersion2, 0xffffffff)),
		"unknown set after":     capsData(general(cbCapsVersion2, cbUseLongFormatNames), capsSet(0x02)),
		"long general set":      capsData(general(cbCapsVersion2, cbUseLongFormatNames, 9, 9, 9, 9)),
		"file and lock flagged": capsData(general(cbCapsVersion2, 0x3e)),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			r.send(rdpServer, r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbClipCaps, 0, data), 0))
			r.expect(rdpClient, r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbClipCaps, 0, want), 0))
		})
	}
	for name, data := range map[string][]byte{
		"no general set":     capsData(capsSet(0x02)),
		"two general sets":   capsData(general(cbCapsVersion2, 0), general(cbCapsVersion2, 0)),
		"short general set":  capsData(capsSet(cbCapsTypeGeneral, 2, 0, 0, 0)),
		"version 3":          capsData(general(3, 0)),
		"version 0":          capsData(general(0, 0)),
		"set past the data":  capsData([]byte{1, 0, 20, 0, 2, 0, 0, 0}),
		"count short":        append(capsData(general(cbCapsVersion1, 0)), capsSet(0x02)...),
		"truncated set head": capsData([]byte{1, 0}),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			r.send(rdpServer, r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbClipCaps, 0, data), 0))
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
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
