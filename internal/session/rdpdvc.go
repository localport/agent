package session

import (
	"bytes"
	"encoding/binary"
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

// rdpDVC is the drdynvc state of a connection, guarded by the filter's mu.
type rdpDVC struct {
	// pending holds the ids of forwarded Create Requests not answered yet,
	// open those the client created.
	pending, open map[uint32]bool
}

func (s *rdpDVC) init() {
	s.pending, s.open = map[uint32]bool{}, map[uint32]bool{}
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
	switch cmd {
	case dvcCreate:
		if from == rdpServer {
			return s.createRequest(msg, id, rest, forward)
		}
		if len(rest) != 4 || !s.pending[id] {
			return nil, rdpViolation("DVC Create Response for channel %d", id)
		}
		delete(s.pending, id)
		if int32(binary.LittleEndian.Uint32(rest)) >= 0 {
			s.open[id] = true
		}
		return forward, nil
	case dvcClose:
		if len(rest) != 0 {
			return nil, rdpViolation("malformed DVC Close")
		}
		if !s.open[id] && (from != rdpServer || !s.pending[id]) {
			return nil, nil
		}
		delete(s.open, id)
		delete(s.pending, id)
		return forward, nil
	case dvcDataFirst:
		if sp == 3 {
			return nil, rdpViolation("DVC Data First length form 3")
		}
		if len(rest) < 1<<sp {
			return nil, rdpViolation("truncated DVC Data First")
		}
	}
	if !s.open[id] {
		return nil, rdpViolation("DVC data on channel %d, not open", id)
	}
	return forward, nil
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
func (s *rdpDVC) createRequest(msg []byte, id uint32, rest []byte, forward []rdpFrame) ([]rdpFrame, error) {
	end := bytes.IndexByte(rest, 0)
	if end != len(rest)-1 {
		return nil, rdpViolation("DVC Create Request name not terminated")
	}
	if s.pending[id] || s.open[id] {
		return nil, rdpViolation("DVC Create Request for channel %d in use", id)
	}
	if string(rest[:end]) != dvcDisplayControl {
		// The id keeps its width: header byte, id, then the status.
		answer := append([]byte{dvcCreate<<4 | msg[0]&0x03}, msg[1:len(msg)-len(rest)]...)
		answer = binary.LittleEndian.AppendUint32(answer, dvcNotFound)
		return []rdpFrame{{to: rdpServer, payload: answer}}, nil
	}
	if len(s.pending)+len(s.open) >= rdpMaxDVCChannels {
		return nil, rdpViolation("%d dynamic channels", len(s.pending)+len(s.open))
	}
	s.pending[id] = true
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
