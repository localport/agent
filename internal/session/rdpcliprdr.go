package session

import (
	"encoding/binary"
	"slices"
)

// CLIPRDR_HEADER msgType and msgFlags values (MS-RDPECLIP 2.2.1).
const (
	cbMonitorReady        = 0x0001
	cbFormatList          = 0x0002
	cbFormatListResponse  = 0x0003
	cbFormatDataRequest   = 0x0004
	cbFormatDataResponse  = 0x0005
	cbTempDirectory       = 0x0006
	cbClipCaps            = 0x0007
	cbFileContentsRequest = 0x0008
	cbFileContentsReply   = 0x0009
	cbLockClipdata        = 0x000a
	cbUnlockClipdata      = 0x000b

	cbResponseOK   = 0x0001
	cbResponseFail = 0x0002
	cbASCIINames   = 0x0004
)

// CLIPRDR_GENERAL_CAPABILITY (MS-RDPECLIP 2.2.2.1.1.1). The filter forwards
// only the long format names flag; file transfer and clipboard locking are
// not offered.
const (
	cbCapsTypeGeneral    = 0x0001
	cbCapsVersion1       = 1
	cbCapsVersion2       = 2
	cbUseLongFormatNames = 0x00000002
)

const (
	// rdpMaxClipText bounds one clipboard transfer, as rfbMaxCutText does.
	rdpMaxClipText = 1 << 20
	// rdpMaxClipPDU bounds a reassembled cliprdr message: a transfer, its
	// header, or a format list.
	rdpMaxClipPDU = rdpMaxClipText + 64<<10
	// rdpMaxClipQueue bounds the outstanding requests and list answers of a
	// direction, as IronRDP bounds its own (ironrdp-cliprdr
	// MAX_PENDING_FORMAT_DATA_REQUESTS).
	rdpMaxClipQueue = 64
	// cbTempDirLen is the wszTempDir field of a Temporary Directory PDU.
	cbTempDirLen = 520
)

// rdpTextFormats are the clipboard formats that carry text: CF_TEXT,
// CF_OEMTEXT, CF_UNICODETEXT and CF_LOCALE.
var rdpTextFormats = []uint32{1, 7, 13, 16}

// clipDir is a clipboard direction: copy moves data from the server to the
// client, paste from the client to the server.
type clipDir uint8

const (
	clipCopy clipDir = iota
	clipPaste
)

// listDir is the direction of a format list from side, which owns the data.
func listDir(from rdpSide) clipDir {
	if from == rdpServer {
		return clipCopy
	}
	return clipPaste
}

// owner is the side whose clipboard d moves.
func (d clipDir) owner() rdpSide {
	if d == clipCopy {
		return rdpServer
	}
	return rdpClient
}

func (d clipDir) allowed(a clipboardAccess) bool {
	if d == clipCopy {
		return a.Copy
	}
	return a.Paste
}

// rdpClipboard is the cliprdr state of a connection, guarded by the
// filter's mu.
type rdpClipboard struct {
	// flags are the general capability flags each side sent.
	flags [2]uint32
	// formats is, per direction, the text formats of the last list the agent
	// forwarded to the receiver; nil when the receiver's view is empty.
	formats [2][]uint32
	// answers is, per direction, the Format List Responses the receiver
	// owes, in order: true for an empty list the agent sent, whose answer
	// it absorbs.
	answers [2][]bool
	// lists is, per direction, the sender's lists still owed an answer, in
	// order: true for one the agent refused, whose Format List Response OK
	// waits for the receiver's answers to every earlier forwarded list.
	lists [2][]bool
	// requests is, per direction, the outstanding Format Data Requests in
	// order: true for one the agent refused, whose RESPONSE_FAIL waits for
	// the answers to every earlier request.
	requests [2][]bool
	// note reports each transfer decision: its direction, outcome and the
	// data bytes it was about. Nil reports none.
	note func(d clipDir, outcome string, n int)
}

// noteDecision reports one transfer decision when a reporter is set.
func (s *rdpClipboard) noteDecision(d clipDir, outcome string, n int) {
	if s.note != nil {
		s.note(d, outcome, n)
	}
}

// name is d's notice direction.
func (d clipDir) name() string {
	if d == clipCopy {
		return clipboardCopy
	}
	return clipboardPaste
}

// clipDataResponseHeader reports whether the first chunk of a total-byte
// cliprdr message is a successful Format Data Response of that size, the
// one message the filter discards past its bound.
func clipDataResponseHeader(first []byte, total int) bool {
	return len(first) >= 8 && binary.LittleEndian.Uint16(first) == cbFormatDataResponse &&
		binary.LittleEndian.Uint16(first[2:]) == cbResponseOK &&
		int(binary.LittleEndian.Uint32(first[4:])) == total-8
}

func cliprdrPDU(typ, flags uint16, data []byte) []byte {
	b := make([]byte, 8, 8+len(data))
	binary.LittleEndian.PutUint16(b, typ)
	binary.LittleEndian.PutUint16(b[2:], flags)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(data)))
	return append(b, data...)
}

// decide applies the clipboard policy to one cliprdr message from side, or,
// with discarded > 0, to a successful Format Data Response of that many data
// bytes discarded past its bound. It returns the PDUs to send.
func (s *rdpClipboard) decide(from rdpSide, msg []byte, discarded int, access clipboardAccess) ([]rdpFrame, error) {
	frames := s.narrow(access)
	if discarded > 0 {
		return s.dataResponse(frames, from, true, access, nil, discarded)
	}
	if len(msg) < 8 {
		return nil, rdpViolation("truncated cliprdr header")
	}
	typ, flags, n := binary.LittleEndian.Uint16(msg), binary.LittleEndian.Uint16(msg[2:]), binary.LittleEndian.Uint32(msg[4:])
	if uint64(n) > uint64(len(msg)-8) {
		return nil, rdpViolation("cliprdr dataLen %d past %d bytes", n, len(msg)-8)
	}
	data := msg[8 : 8+n]
	to := from.other()
	switch typ {
	case cbClipCaps:
		caps, err := s.caps(from, flags, data)
		if err != nil {
			return nil, err
		}
		return append(frames, rdpFrame{to: to, payload: cliprdrPDU(typ, 0, caps)}), nil
	case cbMonitorReady:
		if from != rdpServer || flags != 0 || n != 0 {
			return nil, rdpViolation("cliprdr Monitor Ready from the %s", from.name())
		}
		return append(frames, rdpFrame{to: to, payload: cliprdrPDU(typ, 0, nil)}), nil
	case cbTempDirectory:
		if from != rdpClient || flags != 0 || n != cbTempDirLen {
			return nil, rdpViolation("malformed cliprdr Temporary Directory")
		}
		return frames, nil
	case cbFormatList:
		return s.formatList(frames, from, flags, data, access)
	case cbFormatListResponse:
		if (flags != cbResponseOK && flags != cbResponseFail) || n != 0 {
			return nil, rdpViolation("malformed cliprdr Format List Response")
		}
		// The receiver of a list answers it: lists to the client are copy.
		d := clipCopy
		if from == rdpServer {
			d = clipPaste
		}
		if len(s.answers[d]) == 0 {
			return nil, rdpViolation("cliprdr Format List Response from the %s without a list", from.name())
		}
		absorb := s.answers[d][0]
		s.answers[d] = s.answers[d][1:]
		if absorb {
			return frames, nil
		}
		// The answer to the sender's oldest forwarded list, then the agent's
		// answers to the refused lists it sent after it.
		s.lists[d] = s.lists[d][1:]
		frames = append(frames, rdpFrame{to: to, payload: cliprdrPDU(typ, flags, nil)})
		for len(s.lists[d]) > 0 && s.lists[d][0] {
			s.lists[d] = s.lists[d][1:]
			frames = append(frames, rdpFrame{to: to, payload: cliprdrPDU(cbFormatListResponse, cbResponseOK, nil)})
		}
		return frames, nil
	case cbFormatDataRequest:
		if flags != 0 || n != 4 {
			return nil, rdpViolation("malformed cliprdr Format Data Request")
		}
		// A requester reads the lists it received: the client copies.
		d := clipPaste
		if from == rdpClient {
			d = clipCopy
		}
		if len(s.requests[d]) >= rdpMaxClipQueue {
			return nil, rdpViolation("%d outstanding cliprdr requests", len(s.requests[d]))
		}
		if d.allowed(access) && slices.Contains(s.formats[d], binary.LittleEndian.Uint32(data)) {
			s.requests[d] = append(s.requests[d], false)
			return append(frames, rdpFrame{to: to, payload: cliprdrPDU(typ, 0, data)}), nil
		}
		if d.allowed(access) {
			s.noteDecision(d, clipboardDeniedFormat, 0)
		} else {
			s.noteDecision(d, clipboardDeniedPolicy, 0)
		}
		if len(s.requests[d]) > 0 {
			s.requests[d] = append(s.requests[d], true)
			return frames, nil
		}
		return append(frames, rdpFrame{to: from, payload: cliprdrPDU(cbFormatDataResponse, cbResponseFail, nil)}), nil
	case cbFormatDataResponse:
		switch {
		case flags == cbResponseFail && n == 0:
			return s.dataResponse(frames, from, false, access, nil, 0)
		case flags == cbResponseOK:
			return s.dataResponse(frames, from, true, access, data, len(data))
		}
		return nil, rdpViolation("malformed cliprdr Format Data Response")
	case cbFileContentsRequest:
		if flags != 0 || (n != 24 && n != 28) {
			return nil, rdpViolation("malformed cliprdr File Contents Request")
		}
		// The answer echoes the request's streamId (MS-RDPECLIP 2.2.5.4).
		d := clipPaste
		if from == rdpClient {
			d = clipCopy
		}
		s.noteDecision(d, clipboardDeniedFormat, 0)
		return append(frames, rdpFrame{to: from, payload: cliprdrPDU(cbFileContentsReply, cbResponseFail, data[:4])}), nil
	case cbFileContentsReply:
		if (flags != cbResponseOK && flags != cbResponseFail) || n < 4 {
			return nil, rdpViolation("malformed cliprdr File Contents Response")
		}
		return frames, nil
	case cbLockClipdata, cbUnlockClipdata:
		if flags != 0 || n != 4 {
			return nil, rdpViolation("malformed cliprdr lock PDU")
		}
		return frames, nil
	}
	return nil, rdpViolation("cliprdr message type %#x", typ)
}

// narrow empties the receiver's view of a direction the connection no
// longer allows, as a refused list does.
func (s *rdpClipboard) narrow(access clipboardAccess) []rdpFrame {
	var frames []rdpFrame
	for _, d := range []clipDir{clipCopy, clipPaste} {
		if !d.allowed(access) && s.formats[d] != nil {
			frames = append(frames, s.emptyView(d))
		}
	}
	return frames
}

// emptyView sends the receiver of d an empty format list and absorbs its
// answer.
func (s *rdpClipboard) emptyView(d clipDir) rdpFrame {
	s.formats[d] = nil
	s.answers[d] = append(s.answers[d], true)
	return rdpFrame{to: d.owner().other(), payload: cliprdrPDU(cbFormatList, 0, nil)}
}

// caps reads a Clipboard Capabilities PDU and returns the data the filter
// sends on: one general capability set it builds from the sender's version
// and its long format names flag. Other sets and flags are not forwarded.
func (s *rdpClipboard) caps(from rdpSide, flags uint16, data []byte) ([]byte, error) {
	bad := rdpViolation("malformed cliprdr Clipboard Capabilities")
	if flags != 0 || len(data) < 4 {
		return nil, bad
	}
	count := int(binary.LittleEndian.Uint16(data))
	sets := data[4:]
	var version, general uint32
	seen := false
	for range count {
		if len(sets) < 4 {
			return nil, bad
		}
		typ, n := binary.LittleEndian.Uint16(sets), int(binary.LittleEndian.Uint16(sets[2:]))
		if n < 4 || n > len(sets) {
			return nil, bad
		}
		if typ == cbCapsTypeGeneral {
			if seen || n < 12 {
				return nil, bad
			}
			seen = true
			version = binary.LittleEndian.Uint32(sets[4:])
			general = binary.LittleEndian.Uint32(sets[8:]) & cbUseLongFormatNames
		}
		sets = sets[n:]
	}
	// Without a general set version stays 0 and is refused.
	if len(sets) != 0 || (version != cbCapsVersion1 && version != cbCapsVersion2) {
		return nil, bad
	}
	s.flags[from] = general
	out := make([]byte, 16)
	binary.LittleEndian.PutUint16(out, 1)
	binary.LittleEndian.PutUint16(out[4:], cbCapsTypeGeneral)
	binary.LittleEndian.PutUint16(out[6:], 12)
	binary.LittleEndian.PutUint32(out[8:], version)
	binary.LittleEndian.PutUint32(out[12:], general)
	return out, nil
}

// formatList forwards a list's text formats when its direction is allowed
// and any remain; otherwise it answers the sender itself and empties the
// receiver's view.
func (s *rdpClipboard) formatList(frames []rdpFrame, from rdpSide, flags uint16, data []byte, access clipboardAccess) ([]rdpFrame, error) {
	long := s.flags[rdpServer]&s.flags[rdpClient]&cbUseLongFormatNames != 0
	if flags != 0 && (flags != cbASCIINames || long) {
		return nil, rdpViolation("cliprdr Format List flags %#x", flags)
	}
	var kept []byte
	var ids []uint32
	for len(data) > 0 {
		var entry []byte
		if long {
			// formatId, then a null-terminated UTF-16LE name.
			end := -1
			for i := 4; i+1 < len(data); i += 2 {
				if data[i] == 0 && data[i+1] == 0 {
					end = i + 2
					break
				}
			}
			if end < 0 {
				return nil, rdpViolation("cliprdr long format name without its terminator")
			}
			entry = data[:end]
		} else {
			if len(data) < 36 {
				return nil, rdpViolation("cliprdr short format list of %d bytes", len(data))
			}
			entry = data[:36]
		}
		data = data[len(entry):]
		id := binary.LittleEndian.Uint32(entry)
		if slices.Contains(rdpTextFormats, id) && !slices.Contains(ids, id) {
			ids = append(ids, id)
			kept = append(kept, entry...)
		}
	}
	d := listDir(from)
	if len(s.answers[d]) >= rdpMaxClipQueue || len(s.lists[d]) >= rdpMaxClipQueue {
		return nil, rdpViolation("%d unanswered cliprdr format lists", max(len(s.answers[d]), len(s.lists[d])))
	}
	if d.allowed(access) && len(ids) > 0 {
		s.formats[d] = ids
		s.answers[d] = append(s.answers[d], false)
		s.lists[d] = append(s.lists[d], false)
		return append(frames, rdpFrame{to: from.other(), payload: cliprdrPDU(cbFormatList, flags, kept)}), nil
	}
	if len(s.lists[d]) > 0 {
		s.lists[d] = append(s.lists[d], true)
	} else {
		frames = append(frames, rdpFrame{to: from, payload: cliprdrPDU(cbFormatListResponse, cbResponseOK, nil)})
	}
	if s.formats[d] != nil {
		frames = append(frames, s.emptyView(d))
	}
	return frames, nil
}

// dataResponse answers the oldest outstanding request of the responder's
// direction: its data when ok, the direction is allowed and the data is at
// most rdpMaxClipText bytes, RESPONSE_FAIL otherwise; then the agent's own
// failures queued behind it. size is the response's data length; data is
// shorter when the filter discarded it past its bound. A successful response
// is a transfer decision and is reported; the responder's own failure is not.
func (s *rdpClipboard) dataResponse(frames []rdpFrame, from rdpSide, ok bool, access clipboardAccess, data []byte, size int) ([]rdpFrame, error) {
	d := listDir(from)
	if len(s.requests[d]) == 0 {
		return nil, rdpViolation("cliprdr Format Data Response from the %s without a request", from.name())
	}
	s.requests[d] = s.requests[d][1:]
	to := from.other()
	fail := rdpFrame{to: to, payload: cliprdrPDU(cbFormatDataResponse, cbResponseFail, nil)}
	switch {
	case !ok:
		frames = append(frames, fail)
	case !d.allowed(access):
		s.noteDecision(d, clipboardDeniedPolicy, size)
		frames = append(frames, fail)
	case len(data) != size || size > rdpMaxClipText:
		s.noteDecision(d, clipboardDeniedSize, size)
		frames = append(frames, fail)
	default:
		s.noteDecision(d, clipboardAllowed, size)
		frames = append(frames, rdpFrame{to: to, payload: cliprdrPDU(cbFormatDataResponse, cbResponseOK, data)})
	}
	for len(s.requests[d]) > 0 && s.requests[d][0] {
		s.requests[d] = s.requests[d][1:]
		frames = append(frames, fail)
	}
	return frames, nil
}
