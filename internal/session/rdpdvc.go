package session

import (
	"bytes"
	"encoding/binary"
	"slices"
)

// DVC PDU commands the filter frames (MS-RDPEDYC 2.2); every other command
// ends the connection. DataFirstCompressed (6) and DataCompressed (7) need
// version 3 on both sides, which the filter never lets the client answer,
// and Soft-Sync (8, 9) serves multitransport tunnels, which cannot run over
// the session channel.
const (
	dvcCreate       = 0x01
	dvcDataFirst    = 0x02
	dvcData         = 0x03
	dvcClose        = 0x04
	dvcCapabilities = 0x05
)

const (
	// rdpMaxDVCPDU is the largest DVC PDU (MS-RDPEDYC 2.2.3.1).
	rdpMaxDVCPDU = 1600
	// rdpMaxDVCChannels bounds the dynamic channels pending or open.
	rdpMaxDVCChannels = 8
	// dvcNotFound is the CreationStatus of a refused channel: IronRDP's
	// answer for a listener it does not have (STATUS_NOT_FOUND,
	// ironrdp-dvc CreationStatus::NOT_FOUND).
	dvcNotFound = 0xc0000225
	// dvcDisplayControl is the one dynamic channel the web client opens.
	dvcDisplayControl = "Microsoft::Windows::RDS::DisplayControl"
)

// dvcState is the state of one dynamic channel id. An id with no entry is
// dvcNone.
type dvcState uint8

const (
	dvcNone dvcState = iota
	// dvcPending: the server's Create Request was forwarded; the client owes
	// its Create Response.
	dvcPending
	// dvcOpen: the client created the channel.
	dvcOpen
	// dvcServerClosing: the server's Close was forwarded. What the client sent
	// before it saw that Close (its Create Response, data) is dropped, and
	// its one answering Close passes (MS-RDPEDYC 1.3.3.3, 3.2.5.2).
	dvcServerClosing
	// dvcClientClosed: the client closed the channel or declined it, or the
	// agent refused its Create for the client. Data the server sent before it
	// saw that is dropped; the server does not answer it. IronRDP's client
	// treats a declined channel the same way (ironrdp-dvc client.rs:609-617).
	dvcClientClosed
)

// rdpDVC is the drdynvc state of a connection, guarded by the filter's mu.
// Each PDU moves one id through this table. A Close the table does not list
// is dropped (MS-RDPEDYC 3.2.5.2); any other PDU it does not list ends the
// connection:
//
//	state          server PDU                     client PDU
//	none           Create: pending (or refused)   Close: dropped
//	pending        Close: server-closing          Create Response: open, or client-closed on failure
//	open           Data: forward; Close: s-c      Data: forward; Close: client-closed
//	server-closing Close: dropped                 Create Response: dropped, none on failure;
//	                                              Data: dropped; Close: none
//	client-closed  Create: pending (or refused);  Close: dropped
//	               Data, Close: dropped
//
// A refused Create (a name other than display control) is answered
// STATUS_NOT_FOUND and moves the id to client-closed. At most
// rdpMaxDVCChannels ids are pending, open or server-closing (the client still
// owes its answer); client-closed keeps the most recent rdpMaxDVCChannels
// ids, the oldest falling back to none.
type rdpDVC struct {
	states map[uint32]dvcState
	// closed lists the client-closed ids, oldest first.
	closed []uint32
}

func (s *rdpDVC) init() {
	s.states = map[uint32]dvcState{}
}

// set moves id to st, keeping the client-closed list and its bound.
func (s *rdpDVC) set(id uint32, st dvcState) {
	if i := slices.Index(s.closed, id); i >= 0 {
		s.closed = slices.Delete(s.closed, i, i+1)
	}
	switch st {
	case dvcNone:
		delete(s.states, id)
		return
	case dvcClientClosed:
		if len(s.closed) >= rdpMaxDVCChannels {
			delete(s.states, s.closed[0])
			s.closed = s.closed[1:]
		}
		s.closed = append(s.closed, id)
	}
	s.states[id] = st
}

// live counts the ids pending, open or server-closing.
func (s *rdpDVC) live() int {
	return len(s.states) - len(s.closed)
}

// decide applies the dynamic channel allowlist to one DVC PDU from side and
// returns the PDUs to send.
func (s *rdpDVC) decide(from rdpSide, msg []byte) ([]rdpFrame, error) {
	if len(msg) < 1 {
		return nil, rdpViolation("empty DVC PDU")
	}
	cmd, sp, cb := msg[0]>>4, msg[0]>>2&0x03, msg[0]&0x03
	forward := []rdpFrame{{to: from.other(), payload: msg}}
	switch cmd {
	case dvcCapabilities:
		return s.capabilities(from, msg, forward)
	case dvcCreate, dvcDataFirst, dvcData, dvcClose:
	default:
		return nil, rdpViolation("DVC command %#x from the %s", cmd, from.name())
	}
	id, rest, err := dvcChannelID(msg[1:], cb)
	if err != nil {
		return nil, err
	}
	st := s.states[id]
	switch cmd {
	case dvcCreate:
		if from == rdpServer {
			return s.createRequest(msg, id, rest, st, forward)
		}
		if len(rest) != 4 {
			return nil, rdpViolation("malformed DVC Create Response")
		}
		switch st {
		case dvcPending:
			if int32(binary.LittleEndian.Uint32(rest)) >= 0 {
				s.set(id, dvcOpen)
			} else {
				s.set(id, dvcClientClosed)
			}
			return forward, nil
		case dvcServerClosing:
			// The client answered the Create before it saw the Close. A
			// failure leaves it no channel, so no answering Close follows.
			if int32(binary.LittleEndian.Uint32(rest)) < 0 {
				s.set(id, dvcNone)
			}
			return nil, nil
		}
		return nil, rdpViolation("DVC Create Response for channel %d", id)
	case dvcClose:
		if len(rest) != 0 {
			return nil, rdpViolation("malformed DVC Close")
		}
		return s.close(from, id, st, forward), nil
	case dvcDataFirst:
		if sp == 3 {
			return nil, rdpViolation("DVC Data First length form 3")
		}
		n := 1 << sp
		if len(rest) < n {
			return nil, rdpViolation("truncated DVC Data First")
		}
		var total uint32
		for i := n - 1; i >= 0; i-- {
			total = total<<8 | uint32(rest[i])
		}
		if uint64(total) < uint64(len(rest)-n) {
			return nil, rdpViolation("DVC Data First of %d bytes carries %d", total, len(rest)-n)
		}
	}
	switch {
	case st == dvcOpen:
		return forward, nil
	case from == rdpClient && st == dvcServerClosing, from == rdpServer && st == dvcClientClosed:
		// Sent before the sender saw the other side's Close.
		return nil, nil
	}
	return nil, rdpViolation("DVC data on channel %d, not open", id)
}

// close applies a Close from side to id in state st.
func (s *rdpDVC) close(from rdpSide, id uint32, st dvcState, forward []rdpFrame) []rdpFrame {
	switch {
	case from == rdpServer && (st == dvcPending || st == dvcOpen):
		s.set(id, dvcServerClosing)
		return forward
	case from == rdpClient && st == dvcOpen:
		s.set(id, dvcClientClosed)
		return forward
	case from == rdpClient && st == dvcServerClosing:
		// The client's answer to the server's Close.
		s.set(id, dvcNone)
		return forward
	}
	return nil
}

// capabilities frames a Capabilities Request (version 1 to 3) and the
// client's response, which must be version 1 or 2 (MS-RDPEDYC 2.2.1).
func (s *rdpDVC) capabilities(from rdpSide, msg []byte, forward []rdpFrame) ([]rdpFrame, error) {
	if len(msg) < 4 || msg[1] != 0 {
		return nil, rdpViolation("malformed DVC Capabilities")
	}
	v := binary.LittleEndian.Uint16(msg[2:])
	switch {
	case from == rdpClient && len(msg) == 4 && (v == 1 || v == 2):
	case from == rdpServer && v == 1 && len(msg) == 4,
		from == rdpServer && (v == 2 || v == 3) && len(msg) == 12:
	default:
		return nil, rdpViolation("DVC Capabilities version %d from the %s", v, from.name())
	}
	return forward, nil
}

// createRequest forwards a server's Create Request for the display control
// channel and answers any other with STATUS_NOT_FOUND.
func (s *rdpDVC) createRequest(msg []byte, id uint32, rest []byte, st dvcState, forward []rdpFrame) ([]rdpFrame, error) {
	end := bytes.IndexByte(rest, 0)
	if end != len(rest)-1 {
		return nil, rdpViolation("DVC Create Request name not terminated")
	}
	if st != dvcNone && st != dvcClientClosed {
		return nil, rdpViolation("DVC Create Request for channel %d in use", id)
	}
	// A server may reuse the id of a channel the client closed.
	s.set(id, dvcNone)
	if string(rest[:end]) != dvcDisplayControl {
		// The id keeps its width: header byte, id, then the status.
		answer := append([]byte{dvcCreate<<4 | msg[0]&0x03}, msg[1:len(msg)-len(rest)]...)
		answer = binary.LittleEndian.AppendUint32(answer, dvcNotFound)
		s.set(id, dvcClientClosed)
		return []rdpFrame{{to: rdpServer, payload: answer}}, nil
	}
	if s.live() >= rdpMaxDVCChannels {
		return nil, rdpViolation("%d dynamic channels", s.live())
	}
	s.set(id, dvcPending)
	return forward, nil
}

// dvcChannelID reads a ChannelId of the width cb selects.
func dvcChannelID(b []byte, cb byte) (uint32, []byte, error) {
	switch {
	case cb == 0 && len(b) >= 1:
		return uint32(b[0]), b[1:], nil
	case cb == 1 && len(b) >= 2:
		return uint32(binary.LittleEndian.Uint16(b)), b[2:], nil
	case cb == 2 && len(b) >= 4:
		return binary.LittleEndian.Uint32(b), b[4:], nil
	}
	return 0, nil, rdpViolation("DVC ChannelId of form %d", cb)
}
