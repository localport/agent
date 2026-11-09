package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// CloseDesktopChannelRefused: an rdp client asked for a static virtual
// channel the agent does not allow (MS-RDPBCGR 2.2.1.3.4 CS_NET).
const CloseDesktopChannelRefused = "desktop_channel_refused"

const (
	// rdpMaxTPKT bounds a slow-path PDU: a virtual channel chunk of at most
	// rdpMaxChunk bytes fits with its headers, and a Demand Active or a
	// licensing PDU is a few kilobytes.
	rdpMaxTPKT = 16<<10 + 4
	// rdpMaxTSRequest bounds one CredSSP TSRequest (MS-CSSP 2.2.1).
	rdpMaxTSRequest = 64 << 10
	// rdpMaxFastPath is the largest fast-path length (15 bits).
	rdpMaxFastPath = 0x7fff
	// rdpChunkLength is CHANNEL_CHUNK_LENGTH, the chunk size when either
	// side's Virtual Channel Capability Set omits VCChunkSize, and
	// rdpMaxChunk the largest VCChunkSize (MS-RDPBCGR 2.2.7.1.10, 3.1.5.2.1).
	rdpChunkLength = 1600
	rdpMaxChunk    = 16256
	// rdpMaxStaticChannels is the CS_NET channelCount limit (2.2.1.3.4).
	rdpMaxStaticChannels = 31
	// rdpPumpBuffer holds one whole PDU of either direction.
	rdpPumpBuffer = rdpMaxTSRequest + 16
)

// T.125 DomainMCSPDU choices (the first PER byte shifted right by two) the
// filter frames.
const (
	mcsErectDomainRequest   = 1
	mcsDisconnectUltimatum  = 8
	mcsAttachUserRequest    = 10
	mcsAttachUserConfirm    = 11
	mcsChannelJoinRequest   = 14
	mcsChannelJoinConfirm   = 15
	mcsSendDataRequest      = 25
	mcsSendDataIndication   = 26
	mcsUserIDBase           = 1001
	mcsSendDataPriority     = 0x70
	x224DataHeaderLen       = 3
	x224EOT                 = 0x80
	shareControlDemand      = 0x0011
	shareControlConfirm     = 0x0013
	shareControlDeactivate  = 0x0016
	capsTypeVirtualChannel  = 20
	gccClientNetwork        = 0xc003
	gccServerSecurity       = 0x0c02
	gccServerNetwork        = 0x0c03
	gccServerMessageChannel = 0x0c04
)

// CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1).
const (
	channelFlagFirst            = 0x00000001
	channelFlagLast             = 0x00000002
	channelFlagShowProtocol     = 0x00000010
	channelFlagShadowPersistent = 0x00000080
	channelPacketCompressed     = 0x00200000
	channelPacketAtFront        = 0x00400000
	channelPacketFlushed        = 0x00800000
	channelCompressionTypeMask  = 0x000f0000
	channelFlagsKnown           = channelFlagFirst | channelFlagLast | channelFlagShowProtocol |
		channelFlagShadowPersistent | channelPacketAtFront | channelPacketFlushed
)

// The T.124 object identifier of the GCC Connect PDUs (0.0.20.124.0.1) as
// PER encodes it, and the H.221 keys of client and server data.
var (
	gccObjectID  = []byte{0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01}
	gccClientKey = []byte("Duca")
	gccServerKey = []byte("McDn")
)

// errRDPViolation marks bytes the rdp filter refuses; the connection ends
// desktop_protocol_violation on it.
var errRDPViolation = errors.New("rdp protocol violation")

// errRDPChannelRefused marks a Connect Initial asking for a static channel
// the agent does not allow; the connection ends desktop_channel_refused.
var errRDPChannelRefused = errors.New("rdp channel refused")

func rdpViolation(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRDPViolation, fmt.Sprintf(format, args...))
}

// rdpSide is the peer a PDU came from or goes to.
type rdpSide uint8

const (
	rdpClient rdpSide = iota
	rdpServer
)

func (s rdpSide) other() rdpSide { return 1 - s }

// rdpChannel is a static channel the filter parses.
type rdpChannel uint8

const (
	rdpCliprdr rdpChannel = iota
	rdpDrdynvc
)

// rdpSink is one destination of a filtered rdp connection. A writer holds mu
// for each whole PDU, so PDUs of the two pumps never interleave.
type rdpSink struct {
	mu       sync.Mutex
	w        *bufio.Writer
	writeErr func(error) error
}

func (s *rdpSink) write(b []byte) error {
	if _, err := s.w.Write(b); err != nil {
		return s.writeErr(err)
	}
	return nil
}

func (s *rdpSink) flush() error {
	if err := s.w.Flush(); err != nil {
		return s.writeErr(err)
	}
	return nil
}

// rdpFrame is one PDU a decision sends: an encoded static channel message
// for side to.
type rdpFrame struct {
	to      rdpSide
	channel rdpChannel
	payload []byte
	flags   uint32
}

// rdpFilter frames an rdp connection after the gateway: the CredSSP exchange
// the target's protocol selection calls for, then every slow-path and
// fast-path PDU in both directions on one goroutine each. It allows only the
// static channels the web client uses, reads the negotiated chunk size,
// filters cliprdr per the connection's current clipboard directions and
// drdynvc to the dynamic channels the web client opens.
//
// The pumps share mu, which guards every field below it. A decision on that
// state takes mu, then the sinks it writes in the order toTarget, toClient,
// releases mu and writes, so PDUs reach each sink in decision order while a
// slow sink does not hold up the other pump's decisions.
type rdpFilter struct {
	c        *conn
	protocol uint32
	sinks    [2]*rdpSink
	readers  [2]*bufio.Reader

	mu sync.Mutex
	// authSent: the client's TSRequest carrying authInfo was forwarded.
	authSent bool
	// names are the CS_NET channel names the client asked for, in order.
	names []string
	// io, message and user are the MCS channel ids the server assigned; 0
	// until assigned. channels holds the ids of cliprdr and drdynvc.
	io, message, user uint16
	channels          [2]uint16
	// serverChunk is the server's VCChunkSize, 0 when absent; clientChunk
	// reports whether the client's capability set carried the field.
	serverChunk uint32
	clientChunk bool
	// serverInitiator is the initiator of the server's last Send Data
	// Indication, which agent PDUs toward the client carry.
	serverInitiator uint16
	clip            rdpClipboard
	dvc             rdpDVC
	// beforeSinks, when set, runs in a decision just before it takes the
	// sink locks; tests use it to interleave a decision with a forward.
	beforeSinks func()
}

func newRDPFilter(g *rdpGateway) *rdpFilter {
	return newRDPFilterOver(g.c, g.protocol, g.fromClient, g.ch, g.tls)
}

// newRDPFilterOver frames a connection whose client bytes arrive on
// fromClient (bytes read ahead first), whose client writes go to toClient
// and whose target plaintext is target.
func newRDPFilterOver(c *conn, protocol uint32, fromClient *bufio.Reader, toClient io.Writer, target io.ReadWriter) *rdpFilter {
	f := &rdpFilter{c: c, protocol: protocol}
	f.readers[rdpClient] = fromClient
	f.readers[rdpServer] = bufio.NewReaderSize(target, rfbServerBuffer)
	// sinks[side] is the sink toward side.
	f.sinks[rdpServer] = &rdpSink{w: bufio.NewWriterSize(target, rfbServerBuffer), writeErr: targetIOError}
	f.sinks[rdpClient] = &rdpSink{w: bufio.NewWriterSize(toClient, rfbServerBuffer), writeErr: clientIOError}
	f.dvc.init()
	return f
}

// end maps a direction's end to the relay's end reason.
func (f *rdpFilter) end(err error) string {
	switch {
	case errors.Is(err, errRDPChannelRefused):
		f.c.s.log("session: rdp connection refused: %v", err)
		return CloseDesktopChannelRefused
	case errors.Is(err, errRDPViolation):
		f.c.s.log("session: rdp connection refused: %v", err)
		return CloseDesktopProtocolViolation
	}
	return ""
}

// pumpToTarget frames client PDUs until the connection ends.
func (f *rdpFilter) pumpToTarget() string {
	return f.end(f.newPump(rdpClient).run())
}

// pumpToClient frames server PDUs until the connection ends.
func (f *rdpFilter) pumpToClient() string {
	return f.end(f.newPump(rdpServer).run())
}

// rdpPump is one direction: PDUs from side, forwarded to the other side.
// Only its goroutine uses it.
type rdpPump struct {
	f    *rdpFilter
	from rdpSide
	r    *bufio.Reader
	out  *rdpSink
	buf  []byte
	// connected: the Connect Initial or Connect Response passed.
	connected bool
	// euar: the server's Early User Authorization Result passed.
	euar  bool
	reasm [2]rdpReassembly
}

func (f *rdpFilter) newPump(from rdpSide) *rdpPump {
	return &rdpPump{f: f, from: from, r: f.readers[from], out: f.sinks[from.other()], buf: make([]byte, rdpPumpBuffer)}
}

func (p *rdpPump) readErr(err error) error {
	if p.from == rdpClient {
		return clientIOError(err)
	}
	return targetIOError(err)
}

// peek returns the next byte, flushing what this pump forwarded before a
// read that would block.
func (p *rdpPump) peek() (byte, error) {
	if p.r.Buffered() == 0 {
		p.out.mu.Lock()
		err := p.out.flush()
		p.out.mu.Unlock()
		if err != nil {
			return 0, err
		}
	}
	b, err := p.r.Peek(1)
	if err != nil {
		return 0, p.readErr(err)
	}
	return b[0], nil
}

// read fills p.buf[off:off+n] from the peer.
func (p *rdpPump) read(off, n int) error {
	if p.r.Buffered() < n {
		p.out.mu.Lock()
		err := p.out.flush()
		p.out.mu.Unlock()
		if err != nil {
			return err
		}
	}
	if _, err := io.ReadFull(p.r, p.buf[off:off+n]); err != nil {
		return p.readErr(err)
	}
	if p.from == rdpClient {
		p.f.c.active()
	}
	return nil
}

// forward sends a PDU unchanged.
func (p *rdpPump) forward(b []byte) error {
	p.out.mu.Lock()
	defer p.out.mu.Unlock()
	return p.out.write(b)
}

func (p *rdpPump) run() error {
	if p.f.protocol == rdpProtocolHybrid || p.f.protocol == rdpProtocolHybridEx {
		if err := p.credssp(); err != nil {
			return err
		}
	}
	for {
		b, err := p.peek()
		if err != nil {
			return err
		}
		switch {
		case b == 0x03:
			err = p.slowPath()
		case !p.connected:
			return rdpViolation("%s PDU before the MCS connect", p.from.name())
		case b&0x03 == 0:
			err = p.fastPath()
		default:
			return rdpViolation("%s PDU of action %d", p.from.name(), b&0x03)
		}
		if err != nil {
			return err
		}
	}
}

func (s rdpSide) name() string {
	if s == rdpClient {
		return "client"
	}
	return "server"
}

// credssp frames the CredSSP exchange (MS-CSSP 3.1.5) by its DER outer
// lengths. The client's side is over at its TSRequest carrying authInfo; the
// server's at its Early User Authorization Result under HYBRID_EX
// (MS-RDPBCGR 5.4.2.2), or at the first TPKT under HYBRID.
func (p *rdpPump) credssp() error {
	for {
		b, err := p.peek()
		if err != nil {
			return err
		}
		p.f.mu.Lock()
		authSent := p.f.authSent
		p.f.mu.Unlock()
		switch {
		case b == 0x30:
			n, err := p.readDER()
			if err != nil {
				return err
			}
			if p.from == rdpClient {
				auth, err := tsRequestHasAuthInfo(p.buf[:n])
				if err != nil {
					return err
				}
				if auth {
					// Set before the forward: the server answers it.
					p.f.mu.Lock()
					p.f.authSent = true
					p.f.mu.Unlock()
				}
				if err := p.forward(p.buf[:n]); err != nil {
					return err
				}
				if auth {
					return nil
				}
				continue
			}
			if err := p.forward(p.buf[:n]); err != nil {
				return err
			}
		case p.from == rdpClient:
			return rdpViolation("client CredSSP message is not a TSRequest")
		case !authSent:
			return rdpViolation("server CredSSP message is not a TSRequest")
		case p.f.protocol == rdpProtocolHybridEx && !p.euar:
			if err := p.read(0, 4); err != nil {
				return err
			}
			if v := binary.LittleEndian.Uint32(p.buf); v != 0 && v != 5 {
				return rdpViolation("Early User Authorization Result %#x", v)
			}
			p.euar = true
			if err := p.forward(p.buf[:4]); err != nil {
				return err
			}
		case b == 0x03:
			return nil
		default:
			return rdpViolation("server byte %#x after CredSSP", b)
		}
	}
}

// readDER reads one DER element with a definite length into p.buf and
// returns its size.
func (p *rdpPump) readDER() (int, error) {
	if err := p.read(0, 2); err != nil {
		return 0, err
	}
	n, head := int(p.buf[1]), 2
	switch {
	case n < 0x80:
	case n == 0x81 || n == 0x82:
		k := n & 0x7f
		if err := p.read(2, k); err != nil {
			return 0, err
		}
		n = 0
		for _, b := range p.buf[2 : 2+k] {
			n = n<<8 | int(b)
		}
		head += k
	default:
		return 0, rdpViolation("TSRequest length form %#x", n)
	}
	if head+n > rdpMaxTSRequest {
		return 0, rdpViolation("TSRequest of %d bytes", head+n)
	}
	if err := p.read(head, n); err != nil {
		return 0, err
	}
	return head + n, nil
}

// tsRequestHasAuthInfo reports whether a TSRequest carries authInfo [2]; its
// fields must be well-formed context-tagged elements.
func tsRequestHasAuthInfo(b []byte) (bool, error) {
	body, rest, err := berElement(b, 0x30)
	if err != nil || len(rest) != 0 {
		return false, rdpViolation("malformed TSRequest")
	}
	auth := false
	for len(body) > 0 {
		tag := body[0]
		if tag < 0xa0 || tag > 0xa6 {
			return false, rdpViolation("TSRequest field tag %#x", tag)
		}
		if _, body, err = berElement(body, tag); err != nil {
			return false, rdpViolation("malformed TSRequest field")
		}
		auth = auth || tag == 0xa2
	}
	return auth, nil
}

// berElement splits b into the content of its first element, which must
// carry tag (one or more bytes), and what follows. Lengths are definite, at
// most two bytes.
func berElement(b []byte, tag ...byte) (content, rest []byte, err error) {
	if !bytes.HasPrefix(b, tag) || len(b) < len(tag)+1 {
		return nil, nil, rdpViolation("BER tag")
	}
	b = b[len(tag):]
	n, head := int(b[0]), 1
	switch {
	case n < 0x80:
	case n == 0x81 && len(b) >= 2:
		n, head = int(b[1]), 2
	case n == 0x82 && len(b) >= 3:
		n, head = int(binary.BigEndian.Uint16(b[1:])), 3
	default:
		return nil, nil, rdpViolation("BER length")
	}
	if len(b)-head < n {
		return nil, nil, rdpViolation("BER length past the PDU")
	}
	return b[head : head+n], b[head+n:], nil
}

// perLength reads an aligned PER length determinant of at most 16383.
func perLength(b []byte) (n int, rest []byte, err error) {
	switch {
	case len(b) >= 1 && b[0]&0x80 == 0:
		return int(b[0]), b[1:], nil
	case len(b) >= 2 && b[0]&0xc0 == 0x80:
		return int(b[0]&0x3f)<<8 | int(b[1]), b[2:], nil
	}
	return 0, nil, rdpViolation("PER length")
}

// fastPath forwards one fast-path PDU (MS-RDPBCGR 2.2.8.1.2, 2.2.9.1.2);
// neither form carries channel data.
func (p *rdpPump) fastPath() error {
	if err := p.read(0, 2); err != nil {
		return err
	}
	if p.buf[0]>>6 != 0 {
		return rdpViolation("%s fast-path PDU with security flags %#x", p.from.name(), p.buf[0]>>6)
	}
	n, head := int(p.buf[1]), 2
	if n&0x80 != 0 {
		if err := p.read(2, 1); err != nil {
			return err
		}
		n, head = (n&0x7f)<<8|int(p.buf[2]), 3
	}
	if n <= head || n > rdpMaxFastPath {
		return rdpViolation("%s fast-path length %d", p.from.name(), n)
	}
	if err := p.read(head, n-head); err != nil {
		return err
	}
	return p.forward(p.buf[:n])
}

// slowPath frames one TPKT carrying an X.224 Data TPDU with EOT set and
// one MCS PDU.
func (p *rdpPump) slowPath() error {
	if err := p.read(0, tpktHeaderLen); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(p.buf[2:]))
	if p.buf[1] != 0 || n < tpktHeaderLen+x224DataHeaderLen+1 || n > rdpMaxTPKT {
		return rdpViolation("%s TPKT length %d", p.from.name(), n)
	}
	if err := p.read(tpktHeaderLen, n-tpktHeaderLen); err != nil {
		return err
	}
	pdu := p.buf[:n]
	if pdu[4] != 2 || pdu[5] != 0xf0 || pdu[6] != x224EOT {
		return rdpViolation("%s X.224 TPDU %x is not one Data TPDU", p.from.name(), pdu[4:7])
	}
	mcs := pdu[tpktHeaderLen+x224DataHeaderLen:]
	if !p.connected {
		p.connected = true
		if p.from == rdpClient {
			return p.connectInitial(pdu, mcs)
		}
		return p.connectResponse(pdu, mcs)
	}
	choice, low := mcs[0]>>2, mcs[0]&0x03
	switch {
	case p.from == rdpClient && choice == mcsSendDataRequest && low == 0,
		p.from == rdpServer && choice == mcsSendDataIndication && low == 0:
		return p.sendData(pdu, mcs)
	case p.from == rdpServer && choice == mcsAttachUserConfirm:
		if err := p.attachUserConfirm(mcs); err != nil {
			return err
		}
	case choice == mcsDisconnectUltimatum,
		p.from == rdpClient && (choice == mcsErectDomainRequest || choice == mcsAttachUserRequest || choice == mcsChannelJoinRequest),
		p.from == rdpServer && choice == mcsChannelJoinConfirm:
	default:
		return rdpViolation("%s MCS PDU %#x", p.from.name(), mcs[0])
	}
	return p.forward(pdu)
}

// connectInitial checks the client's MCS Connect Initial (T.125, BER) and
// its GCC Conference Create Request (T.124, PER; MS-RDPBCGR 2.2.1.3) and
// refuses a static channel the agent does not allow before it reaches the
// target.
func (p *rdpPump) connectInitial(pdu, mcs []byte) error {
	ci, rest, err := berElement(mcs, 0x7f, 0x65)
	if err != nil || len(rest) != 0 {
		return rdpViolation("malformed MCS Connect Initial")
	}
	for _, tag := range []byte{0x04, 0x04, 0x01, 0x30, 0x30, 0x30} {
		if _, ci, err = berElement(ci, tag); err != nil {
			return rdpViolation("malformed MCS Connect Initial")
		}
	}
	gcc, rest, err := berElement(ci, 0x04)
	if err != nil || len(rest) != 0 {
		return rdpViolation("malformed MCS Connect Initial user data")
	}
	blocks, err := gccClientData(gcc)
	if err != nil {
		return err
	}
	names, err := clientChannelNames(blocks)
	if err != nil {
		return err
	}
	clipboard := p.f.c.adm.Load().Clipboard
	for _, name := range names {
		switch {
		case name == "drdynvc":
		case name == "cliprdr" && (clipboard.Copy || clipboard.Paste):
		default:
			return fmt.Errorf("%w: static channel %q", errRDPChannelRefused, name)
		}
	}
	p.f.mu.Lock()
	p.f.names = names
	p.f.mu.Unlock()
	return p.forward(pdu)
}

// gccClientData returns the client data blocks of a GCC Conference Create
// Request, encoded as ironrdp-pdu and FreeRDP do.
func gccClientData(b []byte) ([]byte, error) {
	bad := rdpViolation("malformed GCC Conference Create Request")
	if !bytes.HasPrefix(b, gccObjectID) {
		return nil, bad
	}
	_, b, err := perLength(b[len(gccObjectID):])
	if err != nil || len(b) < 3 || b[0] != 0x00 || b[1] != 0x08 {
		return nil, bad
	}
	// conferenceName: a NumericString of at least one digit, two per byte.
	n, b, err := perLength(b[2:])
	if err != nil || len(b) < (n+2)/2+3 {
		return nil, bad
	}
	b = b[(n+2)/2:]
	// padding, one userData set, its h221NonStandard key.
	if b[1] != 0x01 || b[2] != 0xc0 {
		return nil, bad
	}
	if n, b, err = perLength(b[3:]); err != nil || len(b) < n+4 || !bytes.Equal(b[:n+4], gccClientKey) {
		return nil, bad
	}
	if n, b, err = perLength(b[n+4:]); err != nil || len(b) != n {
		return nil, bad
	}
	return b, nil
}

// gccServerData returns the server data blocks of a GCC Conference Create
// Response.
func gccServerData(b []byte) ([]byte, error) {
	bad := rdpViolation("malformed GCC Conference Create Response")
	if !bytes.HasPrefix(b, gccObjectID) {
		return nil, bad
	}
	_, b, err := perLength(b[len(gccObjectID):])
	// choice, nodeID (two bytes), then the tag integer.
	if err != nil || len(b) < 3 {
		return nil, bad
	}
	n, b, err := perLength(b[3:])
	// tag, result, one userData set, its h221NonStandard key.
	if err != nil || len(b) < n+3 || b[n+1] != 0x01 || b[n+2] != 0xc0 {
		return nil, bad
	}
	if n, b, err = perLength(b[n+3:]); err != nil || len(b) < n+4 || !bytes.Equal(b[:n+4], gccServerKey) {
		return nil, bad
	}
	if n, b, err = perLength(b[n+4:]); err != nil || len(b) != n {
		return nil, bad
	}
	return b, nil
}

// gccBlocks calls each for every TS_UD_HEADER block of b with its type and
// body.
func gccBlocks(b []byte, each func(typ uint16, body []byte) error) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return rdpViolation("truncated GCC data block")
		}
		typ, n := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if n < 4 || n > len(b) {
			return rdpViolation("GCC data block %#x of length %d", typ, n)
		}
		if err := each(typ, b[4:n]); err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// clientChannelNames returns the CS_NET channel names, lower case.
func clientChannelNames(blocks []byte) ([]string, error) {
	var names []string
	seenNet := false
	err := gccBlocks(blocks, func(typ uint16, body []byte) error {
		if typ != gccClientNetwork {
			return nil
		}
		if seenNet {
			return rdpViolation("two CS_NET blocks")
		}
		seenNet = true
		if len(body) < 4 {
			return rdpViolation("truncated CS_NET")
		}
		count := binary.LittleEndian.Uint32(body)
		if count > rdpMaxStaticChannels || len(body) != 4+12*int(count) {
			return rdpViolation("CS_NET of %d channels in %d bytes", count, len(body))
		}
		for i := range int(count) {
			raw := body[4+12*i : 4+12*i+8]
			end := bytes.IndexByte(raw, 0)
			if end < 1 {
				return rdpViolation("CS_NET channel name %x", raw)
			}
			name := strings.ToLower(string(raw[:end]))
			for _, r := range name {
				if r < 0x21 || r > 0x7e {
					return rdpViolation("CS_NET channel name %x", raw)
				}
			}
			if slices.Contains(names, name) {
				return rdpViolation("CS_NET names %q twice", name)
			}
			names = append(names, name)
		}
		return nil
	})
	return names, err
}

// connectResponse reads the server's channel ids from its MCS Connect
// Response and checks that it runs no RDP Standard Security.
func (p *rdpPump) connectResponse(pdu, mcs []byte) error {
	bad := rdpViolation("malformed MCS Connect Response")
	cr, rest, err := berElement(mcs, 0x7f, 0x66)
	if err != nil || len(rest) != 0 {
		return bad
	}
	result, cr, err := berElement(cr, 0x0a)
	if err != nil || len(result) != 1 {
		return bad
	}
	for _, tag := range []byte{0x02, 0x30} {
		if _, cr, err = berElement(cr, tag); err != nil {
			return bad
		}
	}
	gcc, rest, err := berElement(cr, 0x04)
	if err != nil || len(rest) != 0 {
		return bad
	}
	if result[0] != 0 {
		// A refusal: the server ends the connection.
		return p.forward(pdu)
	}
	blocks, err := gccServerData(gcc)
	if err != nil {
		return err
	}
	p.f.mu.Lock()
	names := p.f.names
	p.f.mu.Unlock()
	var io, message uint16
	var ids []uint16
	seen := map[uint16]bool{}
	err = gccBlocks(blocks, func(typ uint16, body []byte) error {
		if seen[typ] {
			return rdpViolation("two GCC blocks %#x", typ)
		}
		seen[typ] = true
		switch typ {
		case gccServerSecurity:
			if len(body) < 8 || binary.LittleEndian.Uint64(body) != 0 {
				return rdpViolation("server selected RDP Standard Security encryption")
			}
		case gccServerNetwork:
			if len(body) < 4 {
				return rdpViolation("truncated SC_NET")
			}
			io = binary.LittleEndian.Uint16(body)
			count := int(binary.LittleEndian.Uint16(body[2:]))
			if count != len(names) || len(body) < 4+2*count {
				return rdpViolation("SC_NET of %d channels for %d requested", count, len(names))
			}
			for i := range count {
				ids = append(ids, binary.LittleEndian.Uint16(body[4+2*i:]))
			}
		case gccServerMessageChannel:
			if len(body) < 2 {
				return rdpViolation("truncated SC_MCS_MSGCHANNEL")
			}
			message = binary.LittleEndian.Uint16(body)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !seen[gccServerSecurity] || !seen[gccServerNetwork] || io == 0 {
		return rdpViolation("MCS Connect Response without SC_SECURITY or SC_NET")
	}
	p.f.mu.Lock()
	p.f.io, p.f.message = io, message
	for i, name := range names {
		switch name {
		case "cliprdr":
			p.f.channels[rdpCliprdr] = ids[i]
		case "drdynvc":
			p.f.channels[rdpDrdynvc] = ids[i]
		}
	}
	p.f.mu.Unlock()
	return p.forward(pdu)
}

// attachUserConfirm records the user channel the server assigned.
func (p *rdpPump) attachUserConfirm(mcs []byte) error {
	// The initiator is present only on success (T.125 AttachUserConfirm).
	if mcs[0]&0x02 == 0 {
		return nil
	}
	if len(mcs) != 4 {
		return rdpViolation("malformed MCS Attach User Confirm")
	}
	if mcs[1] == 0 {
		p.f.mu.Lock()
		p.f.user = binary.BigEndian.Uint16(mcs[2:]) + mcsUserIDBase
		p.f.mu.Unlock()
	}
	return nil
}

// sendData frames an MCS Send Data Request or Indication and routes its
// user data by channel.
func (p *rdpPump) sendData(pdu, mcs []byte) error {
	if len(mcs) < 7 {
		return rdpViolation("truncated MCS Send Data")
	}
	initiator, id := binary.BigEndian.Uint16(mcs[1:]), binary.BigEndian.Uint16(mcs[3:])
	n, data, err := perLength(mcs[6:])
	if err != nil || len(data) != n {
		return rdpViolation("MCS Send Data length")
	}
	f := p.f
	f.mu.Lock()
	user := f.user
	if p.from == rdpServer {
		f.serverInitiator = initiator
	}
	kind, isIO := -1, id == f.io
	switch {
	case id == 0:
	case isIO, id == f.message, id == user:
		kind = -2
	case id == f.channels[rdpCliprdr]:
		kind = int(rdpCliprdr)
	case id == f.channels[rdpDrdynvc]:
		kind = int(rdpDrdynvc)
	}
	f.mu.Unlock()
	if p.from == rdpClient && (user == 0 || initiator+mcsUserIDBase != user) {
		return rdpViolation("client Send Data from initiator %d", initiator)
	}
	switch kind {
	case -1:
		return rdpViolation("%s Send Data on channel %d", p.from.name(), id)
	case -2:
		if isIO {
			if err := p.ioChannel(data); err != nil {
				return err
			}
		}
		return p.forward(pdu)
	}
	return p.chunk(rdpChannel(kind), data)
}

// ioChannel reads the Virtual Channel Capability Set from a Demand Active or
// Confirm Active (MS-RDPBCGR 2.2.1.13); a Deactivate All starts a new
// capability exchange. Other I/O channel PDUs pass unread: they carry no
// channel data.
func (p *rdpPump) ioChannel(data []byte) error {
	if len(data) < 6 || int(binary.LittleEndian.Uint16(data)) != len(data) {
		return nil
	}
	typ := binary.LittleEndian.Uint16(data[2:])
	switch {
	case p.from == rdpServer && typ == shareControlDeactivate:
		p.f.mu.Lock()
		p.f.serverChunk, p.f.clientChunk = 0, false
		p.f.mu.Unlock()
		return nil
	case p.from == rdpServer && typ == shareControlDemand, p.from == rdpClient && typ == shareControlConfirm:
	default:
		return nil
	}
	b := data[6:]
	head := 8 // shareId, lengthSourceDescriptor, lengthCombinedCapabilities
	if p.from == rdpClient {
		head = 10 // originatorId follows shareId
	}
	if len(b) < head {
		return rdpViolation("truncated capability PDU")
	}
	source := int(binary.LittleEndian.Uint16(b[head-4:]))
	combined := int(binary.LittleEndian.Uint16(b[head-2:]))
	if combined < 4 || len(b) < head+source+combined {
		return rdpViolation("capability PDU lengths")
	}
	caps := b[head+source : head+source+combined]
	count := int(binary.LittleEndian.Uint16(caps))
	caps = caps[4:]
	var chunk uint32
	found := false
	for range count {
		if len(caps) < 4 {
			return rdpViolation("truncated capability set")
		}
		typ, n := binary.LittleEndian.Uint16(caps), int(binary.LittleEndian.Uint16(caps[2:]))
		if n < 4 || n > len(caps) {
			return rdpViolation("capability set %d of length %d", typ, n)
		}
		if typ == capsTypeVirtualChannel {
			if found || n < 8 {
				return rdpViolation("Virtual Channel Capability Set")
			}
			found = true
			if n >= 12 {
				chunk = binary.LittleEndian.Uint32(caps[8:])
				if p.from == rdpServer && (chunk < rdpChunkLength || chunk > rdpMaxChunk) {
					return rdpViolation("server VCChunkSize %d", chunk)
				}
				if p.from == rdpClient {
					chunk = 1 // the client's value is ignored (2.2.7.1.10)
				}
			}
		}
		caps = caps[n:]
	}
	if len(caps) != 0 {
		return rdpViolation("capability sets past their count")
	}
	p.f.mu.Lock()
	if p.from == rdpServer {
		p.f.serverChunk, p.f.clientChunk = chunk, false
	} else {
		p.f.clientChunk = chunk != 0
	}
	p.f.mu.Unlock()
	return nil
}

// chunkSize is the negotiated virtual channel chunk size (MS-RDPBCGR
// 3.1.5.2.1). Called with mu held.
func (f *rdpFilter) chunkSize() int {
	if f.serverChunk != 0 && f.clientChunk {
		return int(f.serverChunk)
	}
	return rdpChunkLength
}

// rdpReassembly is one direction's virtual channel message in progress.
type rdpReassembly struct {
	active  bool
	discard bool
	total   int
	got     int
	flags   uint32
	buf     []byte
}

// chunk reassembles one virtual channel chunk (MS-RDPBCGR 3.1.5.2.2) and
// handles each whole message.
func (p *rdpPump) chunk(ch rdpChannel, data []byte) error {
	if len(data) < 8 {
		return rdpViolation("truncated CHANNEL_PDU_HEADER")
	}
	total, flags, body := int(binary.LittleEndian.Uint32(data)), binary.LittleEndian.Uint32(data[4:]), data[8:]
	if flags&(channelPacketCompressed|channelCompressionTypeMask) != 0 {
		return rdpViolation("compressed %s chunk", ch.name())
	}
	if flags&^channelFlagsKnown != 0 {
		return rdpViolation("%s chunk flags %#x", ch.name(), flags)
	}
	p.f.mu.Lock()
	size := p.f.chunkSize()
	p.f.mu.Unlock()
	if len(body) > size {
		return rdpViolation("%s chunk of %d bytes past the chunk size %d", ch.name(), len(body), size)
	}
	r := &p.reasm[ch]
	if flags&channelFlagFirst != 0 {
		if r.active {
			return rdpViolation("%s message started inside another", ch.name())
		}
		limit := rdpMaxClipPDU
		if ch == rdpDrdynvc {
			limit = rdpMaxDVCPDU
		}
		*r = rdpReassembly{active: true, total: total, flags: flags & channelFlagShowProtocol, buf: r.buf[:0]}
		if total > limit {
			// Only clipboard data may run past the bound; it is not kept.
			if ch != rdpCliprdr || !clipDataResponseHeader(body, total) {
				return rdpViolation("%s message of %d bytes", ch.name(), total)
			}
			r.discard = true
		}
	} else if !r.active || total != r.total {
		return rdpViolation("%s chunk outside its message", ch.name())
	}
	r.got += len(body)
	if r.got > r.total {
		return rdpViolation("%s message past its length", ch.name())
	}
	if !r.discard {
		r.buf = append(r.buf, body...)
	}
	if flags&channelFlagLast == 0 {
		return nil
	}
	if r.got != r.total {
		return rdpViolation("%s message short of its length", ch.name())
	}
	r.active = false
	msg := r.buf
	if r.discard {
		msg = nil
	}
	return p.f.decide(p.from, ch, msg, r.flags)
}

func (c rdpChannel) name() string {
	if c == rdpCliprdr {
		return "cliprdr"
	}
	return "drdynvc"
}

// decide runs the channel's filter on one whole message from side and sends
// what it decides, holding mu across the decision and the sink locks.
func (f *rdpFilter) decide(from rdpSide, ch rdpChannel, msg []byte, flags uint32) error {
	f.mu.Lock()
	var frames []rdpFrame
	var err error
	if ch == rdpCliprdr {
		frames, err = f.clip.decide(from, msg, f.c.adm.Load().Clipboard)
	} else {
		frames, err = f.dvc.decide(from, msg)
	}
	if err != nil {
		f.mu.Unlock()
		return err
	}
	var wire [2][]byte
	for _, fr := range frames {
		fr.channel, fr.flags = ch, flags
		wire[fr.to] = f.encode(wire[fr.to], fr)
	}
	if f.beforeSinks != nil {
		f.beforeSinks()
	}
	var held []*rdpSink
	for _, side := range []rdpSide{rdpServer, rdpClient} {
		if len(wire[side]) > 0 {
			f.sinks[side].mu.Lock()
			held = append(held, f.sinks[side])
		}
	}
	f.mu.Unlock()
	for _, side := range []rdpSide{rdpServer, rdpClient} {
		if len(wire[side]) == 0 {
			continue
		}
		s := f.sinks[side]
		if err == nil {
			err = s.write(wire[side])
		}
		if err == nil && side != from.other() {
			// An answer to the sender: its pump does not flush this sink.
			err = s.flush()
		}
	}
	for _, s := range held {
		s.mu.Unlock()
	}
	return err
}

// encode appends fr as the chunks of one virtual channel message
// (MS-RDPBCGR 2.2.6.1) at the negotiated chunk size. Called with mu held.
func (f *rdpFilter) encode(dst []byte, fr rdpFrame) []byte {
	size := f.chunkSize()
	choice, initiator := byte(mcsSendDataRequest<<2), f.user-mcsUserIDBase
	if fr.to == rdpClient {
		choice, initiator = mcsSendDataIndication<<2, f.serverInitiator
	}
	id := f.channels[fr.channel]
	msg := fr.payload
	for first := true; first || len(msg) > 0; first = false {
		n := min(len(msg), size)
		flags := fr.flags
		if first {
			flags |= channelFlagFirst
		}
		if n == len(msg) {
			flags |= channelFlagLast
		}
		user := 8 + n
		lenField := 1
		if user >= 0x80 {
			lenField = 2
		}
		tpkt := tpktHeaderLen + x224DataHeaderLen + 6 + lenField + user
		dst = append(dst, 0x03, 0x00, byte(tpkt>>8), byte(tpkt), 0x02, 0xf0, x224EOT, choice)
		dst = binary.BigEndian.AppendUint16(dst, initiator)
		dst = binary.BigEndian.AppendUint16(dst, id)
		dst = append(dst, mcsSendDataPriority)
		if lenField == 2 {
			dst = append(dst, 0x80|byte(user>>8), byte(user))
		} else {
			dst = append(dst, byte(user))
		}
		dst = binary.LittleEndian.AppendUint32(dst, uint32(len(fr.payload)))
		dst = binary.LittleEndian.AppendUint32(dst, flags)
		dst = append(dst, msg[:n]...)
		msg = msg[n:]
	}
	return dst
}
