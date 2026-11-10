package session

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// CloseDesktopProtocolViolation: a desktop connection's bytes left the set
// the agent frames and allows.
const CloseDesktopProtocolViolation = "desktop_protocol_violation"

// RFB security types and Tight sub-authentication types the agent frames
// (noVNC 1.7.0 core/rfb.js).
const (
	rfbSecNone      = 1
	rfbSecVNCAuth   = 2
	rfbSecTight     = 16
	rfbSecXVP       = 22
	rfbSecARD       = 30
	rfbSecMSLogonII = 113
	rfbSecPlain     = 256
	rfbSecUnixLogon = 129
)

// RFB client and server message types the filter frames.
const (
	rfbClientSetPixelFormat   = 0
	rfbClientSetEncodings     = 2
	rfbClientUpdateRequest    = 3
	rfbClientKeyEvent         = 4
	rfbClientPointerEvent     = 5
	rfbClientCutText          = 6
	rfbClientEnableContinuous = 150
	rfbClientFence            = 248
	rfbClientXvp              = 250
	rfbClientSetDesktopSize   = 251
	rfbClientQEMU             = 255

	rfbServerUpdate          = 0
	rfbServerColourMap       = 1
	rfbServerBell            = 2
	rfbServerCutText         = 3
	rfbServerEndOfContinuous = 150
	rfbServerFence           = 248
	rfbServerXvp             = 250
)

// RFB encodings and pseudo-encodings the filter keeps in a SetEncodings.
const (
	rfbEncRaw      int32 = 0
	rfbEncCopyRect int32 = 1
	rfbEncRRE      int32 = 2
	rfbEncHextile  int32 = 5
	rfbEncZlib     int32 = 6
	rfbEncTight    int32 = 7
	rfbEncZRLE     int32 = 16
	rfbEncTightPNG int32 = -260

	rfbEncQualityFirst, rfbEncQualityLast   int32 = -32, -23
	rfbEncCompressFirst, rfbEncCompressLast int32 = -256, -247

	rfbEncDesktopSize         int32 = -223
	rfbEncLastRect            int32 = -224
	rfbEncCursor              int32 = -239
	rfbEncXCursor             int32 = -240
	rfbEncQEMUKeyEvent        int32 = -258
	rfbEncQEMULed             int32 = -261
	rfbEncDesktopName         int32 = -307
	rfbEncExtendedDesktopSize int32 = -308
	rfbEncXvp                 int32 = -309
	rfbEncFence               int32 = -312
	rfbEncContinuousUpdates   int32 = -313
)

const (
	// rfbMaxCutText bounds one clipboard transfer in either direction.
	rfbMaxCutText = 1 << 20
	// rfbMaxReason bounds a refusal reason, a credential and a desktop name.
	rfbMaxReason = 4 << 10
	// rfbMaxEncodings bounds one SetEncodings; noVNC 1.7.0 sends about 30.
	rfbMaxEncodings = 1024
	// rfbMaxCompressed bounds one Zlib or ZRLE rectangle's byte count.
	rfbMaxCompressed = 256 << 20
	// rfbMaxFence bounds a fence payload (RFB community spec: at most 64).
	rfbMaxFence = 64
	// rfbMaxTightCaps bounds each Tight capability list.
	rfbMaxTightTunnels, rfbMaxTightAuths, rfbMaxTightInitCaps = 16, 16, 64
	// rfbMaxARDKey bounds an ARD Diffie-Hellman key.
	rfbMaxARDKey = 512
	// rfbMaxRSAMessage bounds an RA2ne RSA message, 8192 bits of key.
	rfbMaxRSAMessage = 1024
	// rfbMaxRA2Message bounds an RA2ne authenticated message: two lengths and
	// two 255-byte credentials.
	rfbMaxRA2Message = 512

	// rfbServerBuffer sizes the target reader and the channel writer: updates
	// are the bulk of a session, and one read then fills one channel write.
	rfbServerBuffer = 64 << 10
)

// errRFBViolation marks bytes the filter refuses; rfbFilter ends the
// connection desktop_protocol_violation on it.
var errRFBViolation = errors.New("rfb protocol violation")

// errRFBClosed is the handshake's end after the server refused it and the
// refusal was forwarded.
var errRFBClosed = errors.New("rfb handshake refused by the server")

func rfbViolation(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errRFBViolation, fmt.Sprintf(format, args...))
}

// rfbTypeAllowed reports whether t is a top-level security type the agent
// frames (noVNC 1.7.0's list, core/rfb.js _isSupportedSecurityType).
func rfbTypeAllowed(t uint32) bool {
	switch t {
	case rfbSecNone, rfbSecVNCAuth, rfbSecRA2ne, rfbSecTight, rfbSecVeNCrypt, rfbSecXVP, rfbSecARD, rfbSecMSLogonII:
		return true
	}
	return false
}

// rfbSubtypeAllowed reports whether t is a VeNCrypt subtype the agent frames.
// Every subtype that encrypts the stream (TLS and X509) stays out: the filter
// could not read the session.
func rfbSubtypeAllowed(t uint32) bool {
	switch t {
	case rfbSecNone, rfbSecVNCAuth, rfbSecRA2ne, rfbSecTight, rfbSecXVP, rfbSecARD, rfbSecMSLogonII, rfbSecPlain:
		return true
	}
	return false
}

// rfbEncodingBit returns the bit of a kept encoding in rfbFilter.offered, and
// whether the rewritten SetEncodings keeps it. Quality and compress levels
// are settings with no rectangle or message, so they share bit 0, which no
// check reads.
func rfbEncodingBit(e int32) (uint64, bool) {
	switch {
	case e >= rfbEncQualityFirst && e <= rfbEncQualityLast, e >= rfbEncCompressFirst && e <= rfbEncCompressLast:
		return 1 << 0, true
	}
	switch e {
	case rfbEncRaw:
		return 1 << 1, true
	case rfbEncCopyRect:
		return 1 << 2, true
	case rfbEncRRE:
		return 1 << 3, true
	case rfbEncHextile:
		return 1 << 4, true
	case rfbEncZlib:
		return 1 << 5, true
	case rfbEncTight:
		return 1 << 6, true
	case rfbEncZRLE:
		return 1 << 7, true
	case rfbEncTightPNG:
		return 1 << 8, true
	case rfbEncDesktopSize:
		return 1 << 9, true
	case rfbEncLastRect:
		return 1 << 10, true
	case rfbEncCursor:
		return 1 << 11, true
	case rfbEncXCursor:
		return 1 << 12, true
	case rfbEncQEMUKeyEvent:
		return 1 << 13, true
	case rfbEncQEMULed:
		return 1 << 14, true
	case rfbEncDesktopName:
		return 1 << 15, true
	case rfbEncExtendedDesktopSize:
		return 1 << 16, true
	case rfbEncXvp:
		return 1 << 17, true
	case rfbEncFence:
		return 1 << 18, true
	case rfbEncContinuousUpdates:
		return 1 << 19, true
	}
	return 0, false
}

// rfbPixelFormat is what framing needs of a pixel format.
type rfbPixelFormat struct {
	// bytes is one pixel's size.
	bytes uint64
	// tight is one TPIXEL's size: 3 for 32-bit true colour of depth 24 with
	// 8-bit channels (rfbproto.rst, Tight Encoding), otherwise bytes.
	tight uint64
}

// parseRFBPixelFormat parses the 16-byte PIXEL_FORMAT.
func parseRFBPixelFormat(b []byte) (*rfbPixelFormat, error) {
	bits := b[0]
	if bits != 8 && bits != 16 && bits != 32 {
		return nil, rfbViolation("pixel format of %d bits", bits)
	}
	pf := &rfbPixelFormat{bytes: uint64(bits) / 8}
	pf.tight = pf.bytes
	if bits == 32 && b[1] == 24 && b[3] != 0 &&
		binary.BigEndian.Uint16(b[4:]) == 255 && binary.BigEndian.Uint16(b[6:]) == 255 && binary.BigEndian.Uint16(b[8:]) == 255 {
		pf.tight = 3
	}
	return pf, nil
}

// rfbStream forwards bytes from r to w, one direction of a filtered
// connection. Forwarded bytes wait in w only while more input is already
// buffered: every read that would block flushes first.
type rfbStream struct {
	r                 *bufio.Reader
	w                 *bufio.Writer
	readErr, writeErr func(error) error
}

// need returns the next n unconsumed bytes; n is at most r's buffer size. The
// slice is valid until the next read.
func (s *rfbStream) need(n int) ([]byte, error) {
	if s.r.Buffered() < n {
		if err := s.flush(); err != nil {
			return nil, err
		}
	}
	b, err := s.r.Peek(n)
	if err != nil {
		return nil, s.readErr(err)
	}
	return b, nil
}

func (s *rfbStream) flush() error {
	if err := s.w.Flush(); err != nil {
		return s.writeErr(err)
	}
	return nil
}

// forward moves n bytes; n is at most r's buffer size.
func (s *rfbStream) forward(n int) error {
	if n == 0 {
		return nil
	}
	b, err := s.need(n)
	if err != nil {
		return err
	}
	if _, err := s.w.Write(b); err != nil {
		return s.writeErr(err)
	}
	_, _ = s.r.Discard(n)
	return nil
}

// stream moves n bytes as they arrive, holding none of them.
func (s *rfbStream) stream(n uint64) error {
	for n > 0 {
		if _, err := s.need(1); err != nil {
			return err
		}
		k := min(uint64(s.r.Buffered()), n)
		if err := s.forward(int(k)); err != nil {
			return err
		}
		n -= k
	}
	return nil
}

// drop consumes n bytes without forwarding them.
func (s *rfbStream) drop(n uint64) error {
	for n > 0 {
		if _, err := s.need(1); err != nil {
			return err
		}
		k := min(uint64(s.r.Buffered()), n)
		_, _ = s.r.Discard(int(k))
		n -= k
	}
	return nil
}

// rfbFilter frames a VNC connection after the key check: the rest of the
// handshake on the open goroutine, then every message in both directions on
// one goroutine each. It forwards only what it frames, and applies the
// connection's current clipboard directions to each CutText, so a resume that
// narrows them takes effect at the next transfer.
type rfbFilter struct {
	check    *rfbCheck
	c        *conn
	toTarget *rfbStream
	toClient *rfbStream
	// pixelFormat frames rectangles: written by the handshake and by the
	// client goroutine, before the bytes that change it are forwarded.
	pixelFormat atomic.Pointer[rfbPixelFormat]
	// offered is the union of every SetEncodings forwarded, as
	// rfbEncodingBit bits; a union, so a rectangle sent before a later list
	// reached the server still frames. Raw is always offered (RFC 6143 7.7.1).
	offered atomic.Uint64
	// formatFrozen is set by the first SetEncodings,
	// FramebufferUpdateRequest or EnableContinuousUpdates, any of which may
	// make the server send pixels; client goroutine only.
	formatFrozen bool
}

func newRFBFilter(check *rfbCheck, peer io.Writer) *rfbFilter {
	h := check.desktopHandshake
	f := &rfbFilter{
		check: check,
		c:     h.c,
		toTarget: &rfbStream{r: h.fromClient, w: bufio.NewWriter(activityWriter{peer, h.c}),
			readErr: clientIOError, writeErr: targetIOError},
		toClient: &rfbStream{r: h.fromTarget, w: bufio.NewWriterSize(h.ch, rfbServerBuffer),
			readErr: targetIOError, writeErr: clientIOError},
	}
	bit, _ := rfbEncodingBit(rfbEncRaw)
	f.offered.Store(bit)
	return f
}

// arm sets the target deadline of one handshake step.
func (f *rfbFilter) arm() {
	_ = f.check.target.SetDeadline(time.Now().Add(f.check.timeout))
}

// serverSends forwards n handshake bytes from the target at once.
func (f *rfbFilter) serverSends(n int) error {
	f.arm()
	if err := f.toClient.forward(n); err != nil {
		return err
	}
	return f.toClient.flush()
}

// serverLength reads a big-endian length of size bytes from the target,
// refuses it past limit and forwards it.
func (f *rfbFilter) serverLength(size int, limit uint64, what string) (uint64, error) {
	f.arm()
	b, err := f.toClient.need(size)
	if err != nil {
		return 0, err
	}
	n := rfbUint(b)
	if n > limit {
		return 0, rfbViolation("%s of %d bytes", what, n)
	}
	return n, f.serverSends(size)
}

// serverStreams forwards n handshake bytes of any size from the target.
func (f *rfbFilter) serverStreams(n uint64) error {
	f.arm()
	if err := f.toClient.stream(n); err != nil {
		return err
	}
	return f.toClient.flush()
}

// clientSends forwards n handshake bytes from the client at once. The read
// has no deadline, since a person may be typing a password.
func (f *rfbFilter) clientSends(n int) error {
	if err := f.toTarget.forward(n); err != nil {
		return err
	}
	f.arm()
	return f.toTarget.flush()
}

// clientLength reads a big-endian length of size bytes from the client,
// refuses it past limit and forwards it.
func (f *rfbFilter) clientLength(size int, limit uint64, what string) (uint64, error) {
	b, err := f.toTarget.need(size)
	if err != nil {
		return 0, err
	}
	n := rfbUint(b)
	if n > limit {
		return 0, rfbViolation("%s of %d bytes", what, n)
	}
	return n, f.clientSends(size)
}

// clientStreams forwards n handshake bytes of any size from the client.
func (f *rfbFilter) clientStreams(n uint64) error {
	if err := f.toTarget.stream(n); err != nil {
		return err
	}
	f.arm()
	return f.toTarget.flush()
}

// rfbUint is a big-endian unsigned integer of len(b) bytes, at most 8.
func rfbUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// handshake frames everything between the key check and the first message.
// It returns errRFBClosed after forwarding a server's refusal.
func (f *rfbFilter) handshake() error {
	defer func() { _ = f.check.target.SetDeadline(time.Time{}) }()
	switch f.check.refusal {
	case rfbRefusedNoReason:
		return errRFBClosed
	case rfbRefusedWithReason:
		if err := f.forwardReason(); err != nil {
			return err
		}
		return errRFBClosed
	}
	result, err := f.authenticate(f.check.auth)
	if err != nil {
		return err
	}
	if result {
		if err := f.securityResult(); err != nil {
			return err
		}
	}
	if err := f.clientSends(1); err != nil { // ClientInit
		return err
	}
	return f.serverInit()
}

// forwardReason forwards a U32-length refusal reason.
func (f *rfbFilter) forwardReason() error {
	n, err := f.serverLength(4, rfbMaxReason, "refusal reason")
	if err != nil {
		return err
	}
	return f.serverStreams(n)
}

// authenticate frames the authentication of security type t and reports
// whether a SecurityResult follows it.
func (f *rfbFilter) authenticate(t uint32) (result bool, err error) {
	switch t {
	case rfbSecNone:
		return f.check.version == "RFB 003.008\n", nil
	case rfbSecVNCAuth:
		return true, f.vncAuth()
	case rfbSecXVP:
		if err := f.xvp(); err != nil {
			return false, err
		}
		return true, f.vncAuth()
	case rfbSecPlain:
		return true, f.credentials()
	case rfbSecARD:
		return true, f.ard()
	case rfbSecMSLogonII:
		if err := f.serverSends(24); err != nil {
			return false, err
		}
		return true, f.clientStreams(8 + 256 + 64)
	case rfbSecRA2ne:
		return true, f.ra2ne()
	case rfbSecTight:
		return true, f.tight()
	}
	return false, rfbViolation("security type %d", t)
}

func (f *rfbFilter) vncAuth() error {
	if err := f.serverSends(16); err != nil {
		return err
	}
	return f.clientSends(16)
}

// xvp frames the XVP user and target strings, each at most 255 bytes.
func (f *rfbFilter) xvp() error {
	b, err := f.toTarget.need(2)
	if err != nil {
		return err
	}
	n := uint64(b[0]) + uint64(b[1])
	if err := f.clientSends(2); err != nil {
		return err
	}
	return f.clientStreams(n)
}

// credentials frames a U32 user length, a U32 password length and both
// strings: Plain and Tight UnixLogon.
func (f *rfbFilter) credentials() error {
	user, err := f.clientLength(4, rfbMaxReason, "user name")
	if err != nil {
		return err
	}
	pass, err := f.clientLength(4, rfbMaxReason, "password")
	if err != nil {
		return err
	}
	return f.clientStreams(user + pass)
}

func (f *rfbFilter) ard() error {
	if err := f.serverSends(2); err != nil { // generator
		return err
	}
	key, err := f.serverLength(2, rfbMaxARDKey, "ARD key")
	if err != nil {
		return err
	}
	if err := f.serverStreams(2 * key); err != nil { // prime and public key
		return err
	}
	return f.clientStreams(128 + key)
}

// ra2ne frames RA2ne after the server key the check handled, in the order
// noVNC 1.7.0 sends its messages (core/ra2.js negotiateRA2neAuthAsync): each
// side's messages are read in that order, whatever the other side has sent.
func (f *rfbFilter) ra2ne() error {
	// The client's public key: U32 bits, then modulus and exponent.
	b, err := f.toTarget.need(4)
	if err != nil {
		return err
	}
	bits := uint64(binary.BigEndian.Uint32(b))
	if bits < rfbMinKeyBits || bits > rfbMaxKeyBits {
		return rfbViolation("RA2ne client key of %d bits", bits)
	}
	if err := f.clientSends(4); err != nil {
		return err
	}
	if err := f.clientStreams(2 * ((bits + 7) / 8)); err != nil {
		return err
	}
	// The client's random, RSA-encrypted.
	n, err := f.clientLength(2, rfbMaxRSAMessage, "RA2ne client random")
	if err != nil {
		return err
	}
	if err := f.clientStreams(n); err != nil {
		return err
	}
	// The server's random, RSA-encrypted.
	if n, err = f.serverLength(2, rfbMaxRSAMessage, "RA2ne server random"); err != nil {
		return err
	}
	if err := f.serverStreams(n); err != nil {
		return err
	}
	const tag = 16
	// The client's hash, then the server's hash and subtype, then the
	// client's credentials: authenticated messages carrying a tag.
	if n, err = f.clientLength(2, rfbMaxRA2Message, "RA2ne client hash"); err != nil {
		return err
	}
	if err := f.clientStreams(n + tag); err != nil {
		return err
	}
	for range 2 {
		if n, err = f.serverLength(2, rfbMaxRA2Message, "RA2ne server message"); err != nil {
			return err
		}
		if err := f.serverStreams(n + tag); err != nil {
			return err
		}
	}
	if n, err = f.clientLength(2, rfbMaxRA2Message, "RA2ne credentials"); err != nil {
		return err
	}
	return f.clientStreams(n + tag)
}

// tight frames Tight security. Only the NOTUNNEL tunnel and the None, VNCAuth
// and UnixLogon sub-authentications pass.
func (f *rfbFilter) tight() error {
	tunnels, err := f.serverLength(4, rfbMaxTightTunnels, "Tight tunnel list")
	if err != nil {
		return err
	}
	if tunnels > 0 {
		if err := f.serverStreams(16 * tunnels); err != nil {
			return err
		}
		b, err := f.toTarget.need(4)
		if err != nil {
			return err
		}
		if choice := binary.BigEndian.Uint32(b); choice != 0 {
			return rfbViolation("Tight tunnel %d", choice)
		}
		if err := f.clientSends(4); err != nil {
			return err
		}
	}
	auths, err := f.serverLength(4, rfbMaxTightAuths, "Tight authentication list")
	if err != nil {
		return err
	}
	if auths == 0 {
		return nil
	}
	if err := f.serverStreams(16 * auths); err != nil {
		return err
	}
	b, err := f.toTarget.need(4)
	if err != nil {
		return err
	}
	choice := binary.BigEndian.Uint32(b)
	if choice != rfbSecNone && choice != rfbSecVNCAuth && choice != rfbSecUnixLogon {
		return rfbViolation("Tight authentication %d", choice)
	}
	if err := f.clientSends(4); err != nil {
		return err
	}
	switch choice {
	case rfbSecVNCAuth:
		return f.vncAuth()
	case rfbSecUnixLogon:
		return f.credentials()
	}
	return nil
}

// securityResult forwards the result; a failure and its 3.8 reason end the
// handshake.
func (f *rfbFilter) securityResult() error {
	f.arm()
	b, err := f.toClient.need(4)
	if err != nil {
		return err
	}
	status := binary.BigEndian.Uint32(b)
	if err := f.serverSends(4); err != nil {
		return err
	}
	if status == 0 {
		return nil
	}
	if f.check.version == "RFB 003.008\n" {
		if err := f.forwardReason(); err != nil {
			return err
		}
	}
	return errRFBClosed
}

// serverInit frames ServerInit and takes the initial pixel format from it.
func (f *rfbFilter) serverInit() error {
	f.arm()
	b, err := f.toClient.need(24)
	if err != nil {
		return err
	}
	pf, err := parseRFBPixelFormat(b[4:20])
	if err != nil {
		return err
	}
	name := uint64(binary.BigEndian.Uint32(b[20:]))
	if name > rfbMaxReason {
		return rfbViolation("desktop name of %d bytes", name)
	}
	f.pixelFormat.Store(pf)
	if err := f.serverSends(24); err != nil {
		return err
	}
	if err := f.serverStreams(name); err != nil {
		return err
	}
	if f.check.auth != rfbSecTight {
		return nil
	}
	f.arm()
	if b, err = f.toClient.need(8); err != nil {
		return err
	}
	var caps uint64
	for _, c := range []uint16{binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint16(b[4:])} {
		if c > rfbMaxTightInitCaps {
			return rfbViolation("Tight capability list of %d entries", c)
		}
		caps += uint64(c)
	}
	if err := f.serverSends(8); err != nil {
		return err
	}
	return f.serverStreams(16 * caps)
}

// end maps a direction's end to the relay's end reason: a violation's code,
// or "" for a close.
func (f *rfbFilter) end(err error) string {
	if errors.Is(err, errRFBViolation) {
		f.c.s.log("session: vnc connection refused: %v", err)
		return CloseDesktopProtocolViolation
	}
	return ""
}

// pumpToTarget frames client messages until the connection ends.
func (f *rfbFilter) pumpToTarget() string { return f.end(f.clientMessages()) }

// pumpToClient frames server messages until the connection ends.
func (f *rfbFilter) pumpToClient() string { return f.end(f.serverMessages()) }

// requireOffered refuses an extension message whose pseudo-encoding no
// forwarded SetEncodings kept.
func (f *rfbFilter) requireOffered(e int32, message string) error {
	bit, _ := rfbEncodingBit(e)
	if f.offered.Load()&bit == 0 {
		return rfbViolation("%s without its pseudo-encoding", message)
	}
	return nil
}

func (f *rfbFilter) clientMessages() error {
	s := f.toTarget
	for {
		b, err := s.need(1)
		if err != nil {
			return err
		}
		switch b[0] {
		case rfbClientSetPixelFormat:
			err = f.setPixelFormat()
		case rfbClientSetEncodings:
			err = f.setEncodings()
		case rfbClientUpdateRequest:
			f.formatFrozen = true
			err = s.forward(10)
		case rfbClientKeyEvent:
			err = s.forward(8)
		case rfbClientPointerEvent:
			err = s.forward(6)
		case rfbClientCutText:
			err = f.cutText(s, clipboardPaste, f.c.adm.Load().Clipboard.Paste)
		case rfbClientEnableContinuous:
			if err = f.requireOffered(rfbEncContinuousUpdates, "EnableContinuousUpdates"); err == nil {
				f.formatFrozen = true
				err = s.forward(10)
			}
		case rfbClientFence:
			if err = f.requireOffered(rfbEncFence, "ClientFence"); err == nil {
				err = f.fence(s)
			}
		case rfbClientXvp:
			if err = f.requireOffered(rfbEncXvp, "xvp"); err == nil {
				err = s.forward(4)
			}
		case rfbClientSetDesktopSize:
			if err = f.requireOffered(rfbEncExtendedDesktopSize, "SetDesktopSize"); err == nil {
				err = f.setDesktopSize()
			}
		case rfbClientQEMU:
			if err = f.requireOffered(rfbEncQEMUKeyEvent, "QEMU message"); err == nil {
				err = f.qemuMessage()
			}
		default:
			return rfbViolation("client message type %d", b[0])
		}
		if err != nil {
			return err
		}
	}
}

// setPixelFormat takes the new format before forwarding it, and only before
// the format freezes (formatFrozen): later, updates in the old format may be
// in flight and the rectangles could not be framed. It refuses a 24-bit format
// of 8-bit channels at shifts that are not byte-aligned, whose Tight pixel
// size servers do not agree on.
func (f *rfbFilter) setPixelFormat() error {
	if f.formatFrozen {
		return rfbViolation("SetPixelFormat after the format froze")
	}
	b, err := f.toTarget.need(20)
	if err != nil {
		return err
	}
	pf, err := parseRFBPixelFormat(b[4:])
	if err != nil {
		return err
	}
	const redShift, greenShift, blueShift = 14, 15, 16
	if pf.tight == 3 && (b[redShift]%8 != 0 || b[greenShift]%8 != 0 || b[blueShift]%8 != 0) {
		return rfbViolation("24-bit pixel format with channel shifts %d, %d, %d", b[redShift], b[greenShift], b[blueShift])
	}
	f.pixelFormat.Store(pf)
	return f.toTarget.forward(20)
}

// setEncodings forwards the client's list reduced to the kept encodings.
func (f *rfbFilter) setEncodings() error {
	f.formatFrozen = true
	s := f.toTarget
	b, err := s.need(4)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n > rfbMaxEncodings {
		return rfbViolation("SetEncodings of %d entries", n)
	}
	if _, err := s.r.Discard(4); err != nil {
		return s.readErr(err)
	}
	out := make([]byte, 4, 4+4*n)
	out[0] = rfbClientSetEncodings
	var bits uint64
	for range n {
		e, err := s.need(4)
		if err != nil {
			return err
		}
		if bit, ok := rfbEncodingBit(int32(binary.BigEndian.Uint32(e))); ok {
			bits |= bit
			out = append(out, e[:4]...)
		}
		if _, err := s.r.Discard(4); err != nil {
			return s.readErr(err)
		}
	}
	binary.BigEndian.PutUint16(out[2:], uint16((len(out)-4)/4))
	f.offered.Or(bits) // before the server can answer with one of them
	if _, err := s.w.Write(out); err != nil {
		return s.writeErr(err)
	}
	return nil
}

// cutText forwards a CutText moving text in direction when allowed and
// within the size bound, and consumes it otherwise, reporting the decision; a
// negative length is the extended format, which the rewritten SetEncodings
// never requests.
func (f *rfbFilter) cutText(s *rfbStream, direction string, allowed bool) error {
	b, err := s.need(8)
	if err != nil {
		return err
	}
	length := int32(binary.BigEndian.Uint32(b[4:]))
	if length < 0 {
		return rfbViolation("extended CutText")
	}
	n := uint64(length)
	switch {
	case !allowed:
		f.c.noteClipboard("vnc", direction, clipboardDeniedPolicy, int64(length))
	case n > rfbMaxCutText:
		f.c.noteClipboard("vnc", direction, clipboardDeniedSize, int64(length))
	default:
		f.c.noteClipboard("vnc", direction, clipboardAllowed, int64(length))
	}
	if !allowed || n > rfbMaxCutText {
		if _, err := s.r.Discard(8); err != nil {
			return s.readErr(err)
		}
		return s.drop(n)
	}
	if err := s.forward(8); err != nil {
		return err
	}
	return s.stream(n)
}

func (f *rfbFilter) fence(s *rfbStream) error {
	b, err := s.need(9)
	if err != nil {
		return err
	}
	n := int(b[8])
	if n > rfbMaxFence {
		return rfbViolation("fence payload of %d bytes", n)
	}
	return s.forward(9 + n)
}

func (f *rfbFilter) setDesktopSize() error {
	b, err := f.toTarget.need(8)
	if err != nil {
		return err
	}
	return f.toTarget.forward(8 + 16*int(b[6]))
}

// qemuMessage forwards the extended key event, the one QEMU client message
// the kept pseudo-encodings enable.
func (f *rfbFilter) qemuMessage() error {
	b, err := f.toTarget.need(2)
	if err != nil {
		return err
	}
	if b[1] != 0 {
		return rfbViolation("QEMU submessage %d", b[1])
	}
	return f.toTarget.forward(12)
}

func (f *rfbFilter) serverMessages() error {
	s := f.toClient
	for {
		b, err := s.need(1)
		if err != nil {
			return err
		}
		switch b[0] {
		case rfbServerUpdate:
			err = f.update()
		case rfbServerColourMap:
			err = f.colourMap()
		case rfbServerBell, rfbServerEndOfContinuous:
			err = s.forward(1)
		case rfbServerCutText:
			err = f.cutText(s, clipboardCopy, f.c.adm.Load().Clipboard.Copy)
		case rfbServerFence:
			err = f.fence(s)
		case rfbServerXvp:
			err = s.forward(4)
		default:
			return rfbViolation("server message type %d", b[0])
		}
		if err != nil {
			return err
		}
	}
}

func (f *rfbFilter) colourMap() error {
	b, err := f.toClient.need(6)
	if err != nil {
		return err
	}
	n := uint64(binary.BigEndian.Uint16(b[4:]))
	if err := f.toClient.forward(6); err != nil {
		return err
	}
	return f.toClient.stream(6 * n)
}

// update frames a FramebufferUpdate and its rectangles. A LastRect ends the
// update before its count.
func (f *rfbFilter) update() error {
	b, err := f.toClient.need(4)
	if err != nil {
		return err
	}
	rects := int(binary.BigEndian.Uint16(b[2:]))
	if err := f.toClient.forward(4); err != nil {
		return err
	}
	for range rects {
		last, err := f.rectangle()
		if err != nil {
			return err
		}
		if last {
			break
		}
	}
	return nil
}

// rectangle frames one rectangle and reports whether it was a LastRect.
func (f *rfbFilter) rectangle() (last bool, err error) {
	s := f.toClient
	b, err := s.need(12)
	if err != nil {
		return false, err
	}
	w, h := uint64(binary.BigEndian.Uint16(b[4:])), uint64(binary.BigEndian.Uint16(b[6:]))
	encoding := int32(binary.BigEndian.Uint32(b[8:]))
	if bit, ok := rfbEncodingBit(encoding); !ok || f.offered.Load()&bit == 0 {
		return false, rfbViolation("rectangle in encoding %d", encoding)
	}
	if err := s.forward(12); err != nil {
		return false, err
	}
	pf := f.pixelFormat.Load()
	switch encoding {
	case rfbEncRaw:
		return false, s.stream(w * h * pf.bytes)
	case rfbEncCopyRect:
		return false, s.forward(4)
	case rfbEncRRE:
		return false, f.rre(pf)
	case rfbEncHextile:
		return false, f.hextile(w, h, pf)
	case rfbEncZlib, rfbEncZRLE:
		return false, f.lengthPrefixed()
	case rfbEncTight, rfbEncTightPNG:
		return false, f.tightRectangle(w, h, pf)
	case rfbEncDesktopSize, rfbEncQEMUKeyEvent:
		return false, nil
	case rfbEncLastRect:
		return true, nil
	case rfbEncExtendedDesktopSize:
		return false, f.extendedDesktopSize()
	case rfbEncDesktopName:
		return false, f.desktopName()
	case rfbEncCursor:
		return false, s.stream(w*h*pf.bytes + (w+7)/8*h)
	case rfbEncXCursor:
		if w*h == 0 {
			return false, nil
		}
		return false, s.stream(6 + 2*((w+7)/8*h))
	case rfbEncQEMULed:
		return false, s.forward(1)
	}
	return false, rfbViolation("rectangle in setting encoding %d", encoding)
}

func (f *rfbFilter) rre(pf *rfbPixelFormat) error {
	s := f.toClient
	b, err := s.need(4)
	if err != nil {
		return err
	}
	n := uint64(binary.BigEndian.Uint32(b))
	if err := s.forward(4); err != nil {
		return err
	}
	return s.stream(pf.bytes + n*(pf.bytes+8))
}

func (f *rfbFilter) hextile(w, h uint64, pf *rfbPixelFormat) error {
	s := f.toClient
	const (
		raw, background, foreground, anySubrects, coloured = 1, 2, 4, 8, 16
		tile                                               = 16
		known                                              = raw | background | foreground | anySubrects | coloured
	)
	for y := uint64(0); y < h; y += tile {
		th := min(tile, h-y)
		for x := uint64(0); x < w; x += tile {
			tw := min(tile, w-x)
			b, err := s.need(1)
			if err != nil {
				return err
			}
			sub := b[0]
			if sub&^known != 0 {
				return rfbViolation("hextile subencoding %d", sub)
			}
			if err := s.forward(1); err != nil {
				return err
			}
			if sub&raw != 0 {
				if err := s.stream(tw * th * pf.bytes); err != nil {
					return err
				}
				continue
			}
			var pixels uint64
			if sub&background != 0 {
				pixels += pf.bytes
			}
			if sub&foreground != 0 {
				pixels += pf.bytes
			}
			if err := s.forward(int(pixels)); err != nil {
				return err
			}
			if sub&anySubrects == 0 {
				continue
			}
			if b, err = s.need(1); err != nil {
				return err
			}
			size := uint64(b[0]) * 2
			if sub&coloured != 0 {
				size += uint64(b[0]) * pf.bytes
			}
			if err := s.forward(1); err != nil {
				return err
			}
			if err := s.forward(int(size)); err != nil {
				return err
			}
		}
	}
	return nil
}

// lengthPrefixed frames a U32 byte count and its bytes (Zlib, ZRLE).
func (f *rfbFilter) lengthPrefixed() error {
	s := f.toClient
	b, err := s.need(4)
	if err != nil {
		return err
	}
	n := uint64(binary.BigEndian.Uint32(b))
	if n > rfbMaxCompressed {
		return rfbViolation("compressed rectangle of %d bytes", n)
	}
	if err := s.forward(4); err != nil {
		return err
	}
	return s.stream(n)
}

// tightCompact frames a Tight compact length (1 to 3 bytes) and its bytes.
func (f *rfbFilter) tightCompact() error {
	s := f.toClient
	var n uint64
	for i := range 3 {
		b, err := s.need(1)
		if err != nil {
			return err
		}
		c := b[0]
		if err := s.forward(1); err != nil {
			return err
		}
		if i == 2 {
			n |= uint64(c) << 14
			break
		}
		n |= uint64(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			break
		}
	}
	return s.stream(n)
}

// tightRectangle frames a Tight or TightPNG rectangle (rfbproto.rst, Tight
// Encoding; noVNC 1.7.0 core/decoders/tight.js).
func (f *rfbFilter) tightRectangle(w, h uint64, pf *rfbPixelFormat) error {
	s := f.toClient
	b, err := s.need(1)
	if err != nil {
		return err
	}
	control := b[0] >> 4
	if err := s.forward(1); err != nil {
		return err
	}
	const (
		fill, jpeg, png                           = 0x08, 0x09, 0x0a
		basicFlag, explicitFilter                 = 0x08, 0x04
		filterCopy, filterPalette, filterGradient = 0, 1, 2
		minCompressed                             = 12
	)
	switch {
	case control == fill:
		return s.forward(int(pf.tight))
	case control == jpeg, control == png:
		return f.tightCompact()
	case control&basicFlag != 0:
		return rfbViolation("Tight compression control %#x", control)
	}
	filter := byte(filterCopy)
	if control&explicitFilter != 0 {
		if b, err = s.need(1); err != nil {
			return err
		}
		filter = b[0]
		if err := s.forward(1); err != nil {
			return err
		}
	}
	var size uint64
	switch filter {
	case filterCopy, filterGradient:
		size = w * h * pf.tight
	case filterPalette:
		if b, err = s.need(1); err != nil {
			return err
		}
		colours := uint64(b[0]) + 1
		if err := s.forward(1); err != nil {
			return err
		}
		if err := s.forward(int(colours * pf.tight)); err != nil {
			return err
		}
		size = w * h
		if colours <= 2 {
			size = (w + 7) / 8 * h
		}
	default:
		return rfbViolation("Tight filter %d", filter)
	}
	if size < minCompressed {
		return s.stream(size)
	}
	return f.tightCompact()
}

func (f *rfbFilter) extendedDesktopSize() error {
	s := f.toClient
	b, err := s.need(4)
	if err != nil {
		return err
	}
	return s.forward(4 + 16*int(b[0]))
}

func (f *rfbFilter) desktopName() error {
	s := f.toClient
	b, err := s.need(4)
	if err != nil {
		return err
	}
	n := uint64(binary.BigEndian.Uint32(b))
	if n > rfbMaxReason {
		return rfbViolation("desktop name of %d bytes", n)
	}
	if err := s.forward(4); err != nil {
		return err
	}
	return s.stream(n)
}
