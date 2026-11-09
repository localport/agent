//go:build linux || darwin

package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// noDeadlineConn is a target connection whose deadlines do nothing.
type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error { return nil }

// filterRun is an rfbFilter over fixed client and server bytes, with what it
// forwarded each way.
type filterRun struct {
	*rfbFilter
	toServer, toClientOut bytes.Buffer
}

func newFilterRun(clipboard clipboardAccess, version string, auth uint32, fromClient, fromServer []byte) *filterRun {
	c := &conn{s: NewServer(ServerConfig{}), failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	c.adm.Store(&connAdmission{admission: &admission{Kind: "vnc", Clipboard: clipboard}})
	h := &desktopHandshake{c: c, target: noDeadlineConn{}, timeout: time.Minute,
		fromClient: bufio.NewReader(bytes.NewReader(fromClient)), fromTarget: bufio.NewReader(bytes.NewReader(fromServer))}
	r := &filterRun{}
	r.rfbFilter = newRFBFilter(&rfbCheck{desktopHandshake: h, version: version, auth: auth}, &r.toServer)
	r.toClient.w.Reset(&r.toClientOut)
	r.pixelFormat.Store(&rfbPixelFormat{bytes: 4, tight: 3})
	return r
}

// wantViolation fails unless err is a protocol violation.
func wantViolation(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errRFBViolation) {
		t.Fatalf("got %v, want a protocol violation", err)
	}
}

// wantClosed fails unless err is the input's end, not a violation.
func wantClosed(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want the input's end", err)
	}
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func join(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func fill(n int) []byte { return bytes.Repeat([]byte{0x5a}, n) }

const (
	rfbV33 = "RFB 003.003\n"
	rfbV37 = "RFB 003.007\n"
	rfbV38 = "RFB 003.008\n"
)

var securityOK = be32(0)

// Every framing-table row forwards each side's bytes unchanged through
// ServerInit, and a failed result ends it with its reason forwarded.
func TestRFBHandshakeFraming(t *testing.T) {
	init := rfbServerInit()
	tightInit := join(init, be16(1), be16(2), be16(1), be16(0), fill(16*4))
	plain := join(be32(3), be32(4), fill(7))
	ard := join(fill(2), be16(4), fill(8))
	tunnels := join(be32(1), fill(16))
	auths := func(n uint32) []byte { return join(be32(n), fill(int(16*n))) }
	ra2Client := join(ra2ClientFirst(), ra2Sealed(20), ra2Sealed(9))
	ra2Srv := join(ra2Message(128), ra2Sealed(20), ra2Sealed(1))
	for _, tc := range []struct {
		name    string
		version string
		auth    uint32
		client  []byte
		server  []byte
	}{
		{"none 3.8", rfbV38, rfbSecNone, []byte{1}, join(securityOK, init)},
		{"none 3.7 has no result", rfbV37, rfbSecNone, []byte{1}, init},
		{"none 3.3 has no result", rfbV33, rfbSecNone, []byte{1}, init},
		{"vnc auth", rfbV38, rfbSecVNCAuth, join(fill(16), []byte{1}), join(fill(16), securityOK, init)},
		{"xvp then vnc auth", rfbV38, rfbSecXVP, join([]byte{2, 3}, fill(5), fill(16), []byte{1}), join(fill(16), securityOK, init)},
		{"plain", rfbV38, rfbSecPlain, join(plain, []byte{1}), join(securityOK, init)},
		{"ard", rfbV38, rfbSecARD, join(fill(128+4), []byte{1}), join(ard, securityOK, init)},
		{"ms logon ii", rfbV38, rfbSecMSLogonII, join(fill(8+256+64), []byte{1}), join(fill(24), securityOK, init)},
		{"ra2ne", rfbV38, rfbSecRA2ne, join(ra2Client, []byte{1}), join(ra2Srv, securityOK, init)},
		{"tight no tunnels no auth", rfbV38, rfbSecTight, []byte{1}, join(be32(0), be32(0), securityOK, tightInit)},
		{"tight notunnel none", rfbV38, rfbSecTight, join(be32(0), be32(rfbSecNone), []byte{1}), join(tunnels, auths(1), securityOK, tightInit)},
		{"tight vnc auth", rfbV38, rfbSecTight, join(be32(rfbSecVNCAuth), fill(16), []byte{1}), join(be32(0), auths(2), fill(16), securityOK, tightInit)},
		{"tight unix logon", rfbV38, rfbSecTight, join(be32(rfbSecUnixLogon), plain, []byte{1}), join(be32(0), auths(1), securityOK, tightInit)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, tc.version, tc.auth, tc.client, tc.server)
			if err := r.handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if err := r.toTarget.flush(); err != nil {
				t.Fatal(err)
			}
			if err := r.toClient.flush(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(r.toServer.Bytes(), tc.client) {
				t.Fatalf("server got % x, want % x", r.toServer.Bytes(), tc.client)
			}
			if !bytes.Equal(r.toClientOut.Bytes(), tc.server) {
				t.Fatalf("client got % x, want % x", r.toClientOut.Bytes(), tc.server)
			}
		})
	}
}

// A failed SecurityResult is forwarded and ends the handshake: with its
// reason under 3.8, without one under 3.7. A refusal found by the check
// forwards its reason.
func TestRFBHandshakeRefusals(t *testing.T) {
	reason := join(be32(4), []byte("nope"))
	for _, tc := range []struct {
		name    string
		version string
		auth    uint32
		client  []byte
		refusal rfbRefusal
		server  []byte
	}{
		{"result 3.8", rfbV38, rfbSecNone, nil, 0, join(be32(1), reason)},
		{"result 3.7", rfbV37, rfbSecVNCAuth, fill(16), 0, join(fill(16), be32(1))},
		{"type refused", rfbV38, rfbSecNone, nil, rfbRefusedWithReason, reason},
		{"vencrypt refused", rfbV38, rfbSecNone, nil, rfbRefusedNoReason, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, tc.version, tc.auth, tc.client, tc.server)
			r.check.refusal = tc.refusal
			if err := r.handshake(); !errors.Is(err, errRFBClosed) {
				t.Fatalf("handshake: %v, want the refusal's end", err)
			}
			if !bytes.Equal(r.toClientOut.Bytes(), tc.server) {
				t.Fatalf("client got % x, want % x", r.toClientOut.Bytes(), tc.server)
			}
		})
	}
}

// Every length and choice of the handshake is bounded before it is read.
func TestRFBHandshakeBounds(t *testing.T) {
	long := func(pixelInit []byte, name uint32) []byte {
		return join(pixelInit[:20], be32(name))
	}
	init := rfbServerInit()
	for _, tc := range []struct {
		name   string
		auth   uint32
		client []byte
		server []byte
	}{
		{"reason", rfbSecVNCAuth, fill(16), join(fill(16), be32(1), be32(rfbMaxReason+1))},
		{"plain user", rfbSecPlain, be32(rfbMaxReason + 1), nil},
		{"plain password", rfbSecPlain, join(be32(1), be32(rfbMaxReason+1)), nil},
		{"ard key", rfbSecARD, nil, join(fill(2), be16(rfbMaxARDKey+1))},
		{"ra2 client key", rfbSecRA2ne, be32(512), nil},
		{"ra2 client random", rfbSecRA2ne, join(ra2ClientKey(), be16(rfbMaxRSAMessage+1)), nil},
		{"tight tunnels", rfbSecTight, nil, be32(rfbMaxTightTunnels + 1)},
		{"tight tunnel choice", rfbSecTight, be32(1), join(be32(1), fill(16))},
		{"tight auths", rfbSecTight, nil, join(be32(0), be32(rfbMaxTightAuths+1))},
		{"tight auth choice", rfbSecTight, be32(5), join(be32(0), be32(1), fill(16))},
		{"name", rfbSecNone, []byte{1}, join(securityOK, long(init, rfbMaxReason+1))},
		{"pixel format", rfbSecNone, []byte{1}, join(securityOK, init[:4], []byte{24}, init[5:])},
		{"tight init caps", rfbSecTight, []byte{1}, join(be32(0), be32(0), securityOK, init, be16(rfbMaxTightInitCaps+1), be16(0), be16(0), be16(0))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, rfbV38, tc.auth, tc.client, tc.server)
			wantViolation(t, r.handshake())
		})
	}
}

// noVNC 1.7.0's list loses exactly the encodings the filter does not frame,
// in order; a rectangle in a removed encoding then ends the session.
func TestRFBSetEncodingsRewrite(t *testing.T) {
	const (
		jpeg, h264            = 21, 50
		vmware                = 0x574d5664
		extendedClipboard     = -1063131698 // 0xC0A1E5CE
		clipboardAvailability = -318
		extendedMouse         = -316
		cursorWithAlpha       = -314
		trle                  = 15
	)
	sent := []int32{rfbEncCopyRect, h264, rfbEncTight, rfbEncTightPNG, rfbEncZRLE, jpeg, rfbEncHextile, rfbEncRRE, rfbEncZlib, rfbEncRaw,
		-32 + 6, -256 + 2, rfbEncDesktopSize, rfbEncLastRect, rfbEncQEMUKeyEvent, rfbEncQEMULed, rfbEncExtendedDesktopSize, rfbEncXvp,
		rfbEncFence, rfbEncContinuousUpdates, rfbEncDesktopName, extendedClipboard, extendedMouse, vmware, rfbEncCursor,
		clipboardAvailability, cursorWithAlpha, trle, rfbEncXCursor}
	want := []int32{rfbEncCopyRect, rfbEncTight, rfbEncTightPNG, rfbEncZRLE, rfbEncHextile, rfbEncRRE, rfbEncZlib, rfbEncRaw,
		-32 + 6, -256 + 2, rfbEncDesktopSize, rfbEncLastRect, rfbEncQEMUKeyEvent, rfbEncQEMULed, rfbEncExtendedDesktopSize, rfbEncXvp,
		rfbEncFence, rfbEncContinuousUpdates, rfbEncDesktopName, rfbEncCursor, rfbEncXCursor}
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, setEncodings(sent...), nil)
	wantClosed(t, r.clientMessages())
	if got := r.toServer.Bytes(); !bytes.Equal(got, setEncodings(want...)) {
		t.Fatalf("server got % x, want % x", got, setEncodings(want...))
	}
	for _, removed := range []int32{jpeg, h264, extendedMouse, trle, cursorWithAlpha} {
		f := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, setEncodings(sent...), update(rect(1, 1, removed)))
		wantClosed(t, f.clientMessages())
		wantViolation(t, f.serverMessages())
	}
	long := append(be32(uint32(rfbClientSetEncodings)<<24), be32(0)...)
	binary.BigEndian.PutUint16(long[2:], rfbMaxEncodings+1)
	wantViolation(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, long, nil).clientMessages())
}

func setEncodings(list ...int32) []byte {
	b := join([]byte{rfbClientSetEncodings, 0}, be16(uint16(len(list))))
	for _, e := range list {
		b = binary.BigEndian.AppendUint32(b, uint32(e))
	}
	return b
}

func update(rects ...[]byte) []byte {
	return join([]byte{rfbServerUpdate, 0}, be16(uint16(len(rects))), join(rects...))
}

func rect(w, h uint16, encoding int32, body ...[]byte) []byte {
	return join(be16(0), be16(0), be16(w), be16(h), be32(uint32(encoding)), join(body...))
}

// allEncodings offers every encoding the filter keeps.
func allEncodings() []byte {
	return setEncodings(rfbEncCopyRect, rfbEncRRE, rfbEncHextile, rfbEncZlib, rfbEncZRLE, rfbEncTight, rfbEncTightPNG,
		rfbEncDesktopSize, rfbEncLastRect, rfbEncExtendedDesktopSize, rfbEncDesktopName, rfbEncCursor, rfbEncXCursor,
		rfbEncQEMUKeyEvent, rfbEncQEMULed, rfbEncFence, rfbEncContinuousUpdates, rfbEncXvp)
}

// Each kept encoding's rectangle is framed exactly: a Bell placed after a
// sequence of them is still read as a message.
func TestRFBRectangleFraming(t *testing.T) {
	bell := []byte{rfbServerBell}
	tightPixels := func(n int) []byte { return fill(n) }
	for _, tc := range []struct {
		name string
		rect []byte
	}{
		{"raw", rect(3, 2, rfbEncRaw, fill(24))},
		{"copy rect", rect(3, 2, rfbEncCopyRect, fill(4))},
		{"rre", rect(3, 2, rfbEncRRE, be32(2), fill(4), fill(2*12))},
		{"hextile raw tile", rect(17, 1, rfbEncHextile, []byte{1}, fill(16*4), []byte{1}, fill(4))},
		{"hextile background and foreground", rect(4, 4, rfbEncHextile, []byte{2 | 4}, fill(8))},
		{"hextile plain subrects", rect(4, 4, rfbEncHextile, []byte{2 | 8}, fill(4), []byte{3}, fill(6))},
		{"hextile coloured subrects", rect(4, 4, rfbEncHextile, []byte{8 | 16, 2}, fill(12))},
		{"hextile no data", rect(4, 4, rfbEncHextile, []byte{0})},
		{"zlib", rect(3, 2, rfbEncZlib, be32(5), fill(5))},
		{"zrle", rect(3, 2, rfbEncZRLE, be32(5), fill(5))},
		{"tight fill", rect(3, 2, rfbEncTight, []byte{0x80}, tightPixels(3))},
		{"tight jpeg one length byte", rect(3, 2, rfbEncTight, []byte{0x90, 5}, fill(5))},
		{"tight jpeg three length bytes", rect(3, 2, rfbEncTight, []byte{0x90, 0x80, 0x80, 1}, fill(1<<14))},
		{"tight png", rect(3, 2, rfbEncTightPNG, []byte{0xa0, 4}, fill(4))},
		{"tight basic copy short", rect(1, 1, rfbEncTight, []byte{0x00}, tightPixels(3))},
		{"tight basic copy compressed", rect(4, 4, rfbEncTight, []byte{0x00, 6}, fill(6))},
		{"tight palette two colours", rect(9, 1, rfbEncTight, []byte{0x40, 1, 1}, tightPixels(6), fill(2))},
		{"tight palette one colour", rect(9, 1, rfbEncTight, []byte{0x40, 1, 0}, tightPixels(3), fill(2))},
		{"tight palette compressed", rect(13, 1, rfbEncTight, []byte{0x40, 1, 2}, tightPixels(9), []byte{3}, fill(3))},
		{"tight gradient", rect(1, 2, rfbEncTight, []byte{0x40, 2}, tightPixels(6))},
		{"desktop size", rect(9, 9, rfbEncDesktopSize)},
		{"extended desktop size", rect(9, 9, rfbEncExtendedDesktopSize, []byte{2, 0, 0, 0}, fill(32))},
		{"desktop name", rect(0, 0, rfbEncDesktopName, be32(3), fill(3))},
		{"cursor", rect(9, 2, rfbEncCursor, fill(9*2*4), fill(4))},
		{"xcursor", rect(9, 2, rfbEncXCursor, fill(6), fill(8))},
		{"xcursor empty", rect(0, 0, rfbEncXCursor)},
		{"qemu key event", rect(0, 0, rfbEncQEMUKeyEvent)},
		{"qemu led", rect(0, 0, rfbEncQEMULed, fill(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := join(update(tc.rect, tc.rect), bell)
			r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, allEncodings(), server)
			wantClosed(t, r.clientMessages())
			wantClosed(t, r.serverMessages())
			if !bytes.Equal(r.toClientOut.Bytes(), server) {
				t.Fatalf("client got %d bytes, want %d", r.toClientOut.Len(), len(server))
			}
		})
	}
}

// LastRect ends an update before its count, so the next byte is a message.
func TestRFBLastRect(t *testing.T) {
	head := []byte{rfbServerUpdate, 0, 0xff, 0xff}
	server := join(head, rect(1, 1, rfbEncRaw, fill(4)), rect(0, 0, rfbEncLastRect), []byte{rfbServerBell})
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, allEncodings(), server)
	wantClosed(t, r.clientMessages())
	wantClosed(t, r.serverMessages())
	if !bytes.Equal(r.toClientOut.Bytes(), server) {
		t.Fatalf("client got % x", r.toClientOut.Bytes())
	}
}

// A rectangle that breaks its encoding's rules ends the session.
func TestRFBRectangleRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		rect []byte
	}{
		{"zlib too long", rect(1, 1, rfbEncZlib, be32(rfbMaxCompressed+1))},
		{"hextile unknown bit", rect(1, 1, rfbEncHextile, []byte{0x20})},
		{"tight unknown control", rect(1, 1, rfbEncTight, []byte{0xb0})},
		{"tight unknown filter", rect(1, 1, rfbEncTight, []byte{0x40, 3})},
		{"desktop name too long", rect(0, 0, rfbEncDesktopName, be32(rfbMaxReason+1))},
		{"a setting encoding", rect(0, 0, -30)},
		{"fence as a rectangle", rect(0, 0, rfbEncFence)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(allEncodings(), setEncodings(-30)), update(tc.rect))
			wantClosed(t, r.clientMessages())
			wantViolation(t, r.serverMessages())
		})
	}
}

// Raw is offered without a SetEncodings; every other encoding needs one.
func TestRFBRectangleNeedsItsEncoding(t *testing.T) {
	raw := update(rect(1, 1, rfbEncRaw, fill(4)))
	wantClosed(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, nil, raw).serverMessages())
	wantViolation(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, nil, update(rect(1, 1, rfbEncHextile, []byte{0}))).serverMessages())
}

// A rectangle's body reaches the client as it arrives, before the rest of it
// exists.
func TestRFBRectangleStreams(t *testing.T) {
	serverSide, filterSide := net.Pipe()
	defer serverSide.Close()
	defer filterSide.Close()
	var out syncBuffer
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, nil, nil)
	r.toClient.r = bufio.NewReader(filterSide)
	r.toClient.w.Reset(&out)
	go func() { _ = r.serverMessages() }()
	head := join([]byte{rfbServerUpdate, 0}, be16(1), rect(1000, 1000, rfbEncRaw))
	if _, err := serverSide.Write(join(head, fill(10))); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for out.n.Load() < int64(len(head)+10) {
		if time.Now().After(deadline) {
			t.Fatalf("%d bytes forwarded of a partial rectangle, want %d", out.n.Load(), len(head)+10)
		}
		time.Sleep(time.Millisecond)
	}
}

// syncBuffer counts what was written to it.
type syncBuffer struct{ n atomic.Int64 }

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.n.Add(int64(len(p)))
	return len(p), nil
}

// Client messages: the fixed set passes unchanged, extensions pass only with
// their pseudo-encoding, and anything else ends the session.
func TestRFBClientMessages(t *testing.T) {
	offered := setEncodings(rfbEncContinuousUpdates, rfbEncFence, rfbEncXvp, rfbEncExtendedDesktopSize, rfbEncQEMUKeyEvent)
	messages := map[string][]byte{
		"update request":     join([]byte{rfbClientUpdateRequest}, fill(9)),
		"key event":          join([]byte{rfbClientKeyEvent}, fill(7)),
		"pointer event":      join([]byte{rfbClientPointerEvent}, fill(5)),
		"continuous updates": join([]byte{rfbClientEnableContinuous}, fill(9)),
		"fence":              join([]byte{rfbClientFence}, fill(7), []byte{3}, fill(3)),
		"xvp":                join([]byte{rfbClientXvp}, fill(3)),
		"desktop size":       join([]byte{rfbClientSetDesktopSize}, fill(5), []byte{1, 0}, fill(16)),
		"qemu extended key":  join([]byte{rfbClientQEMU, 0}, fill(10)),
	}
	gated := map[string]bool{"continuous updates": true, "fence": true, "xvp": true, "desktop size": true, "qemu extended key": true}
	for name, msg := range messages {
		t.Run(name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(offered, msg), nil)
			wantClosed(t, r.clientMessages())
			if got := r.toServer.Bytes()[len(offered):]; !bytes.Equal(got, msg) {
				t.Fatalf("server got % x, want % x", got, msg)
			}
			if gated[name] {
				wantViolation(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, msg, nil).clientMessages())
			}
		})
	}
	for name, msg := range map[string][]byte{
		"unknown type":     {99},
		"extended pointer": {7},
		"qemu submessage":  join([]byte{rfbClientQEMU, 1}, fill(10)),
		"long fence":       join([]byte{rfbClientFence}, fill(7), []byte{rfbMaxFence + 1}),
	} {
		t.Run(name, func(t *testing.T) {
			r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(offered, msg), nil)
			wantViolation(t, r.clientMessages())
			if err := r.toTarget.flush(); err != nil {
				t.Fatal(err)
			}
			if got := r.toServer.Bytes(); len(got) > len(offered) {
				t.Fatalf("the refused message reached the server: % x", got[len(offered):])
			}
		})
	}
}

// Server messages other than the allowed set end the session.
func TestRFBServerMessages(t *testing.T) {
	server := join([]byte{rfbServerColourMap, 0}, be16(0), be16(2), fill(12), []byte{rfbServerBell, rfbServerEndOfContinuous},
		[]byte{rfbServerFence}, fill(7), []byte{2}, fill(2), []byte{rfbServerXvp}, fill(3))
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, nil, server)
	wantClosed(t, r.serverMessages())
	if !bytes.Equal(r.toClientOut.Bytes(), server) {
		t.Fatalf("client got % x", r.toClientOut.Bytes())
	}
	for _, msg := range [][]byte{{99}, join([]byte{rfbServerFence}, fill(7), []byte{rfbMaxFence + 1})} {
		wantViolation(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, nil, msg).serverMessages())
	}
}

func cutText(kind byte, length int32, body []byte) []byte {
	return join([]byte{kind}, fill(3), be32(uint32(length)), body)
}

// CutText moves only in a direction the certificate allows, for all four
// option values; a refused one is consumed and the stream stays framed.
func TestRFBCutTextPerDirection(t *testing.T) {
	text := []byte("clip")
	for _, clipboard := range []clipboardAccess{{}, {Copy: true}, {Paste: true}, {Copy: true, Paste: true}} {
		fromServer := join(cutText(rfbServerCutText, 4, text), []byte{rfbServerBell})
		fromClient := join(cutText(rfbClientCutText, 4, text), []byte{rfbClientKeyEvent}, fill(7))
		r := newFilterRun(clipboard, rfbV38, rfbSecNone, fromClient, fromServer)
		wantClosed(t, r.serverMessages())
		wantClosed(t, r.clientMessages())

		wantClient := []byte{rfbServerBell}
		if clipboard.Copy {
			wantClient = fromServer
		}
		if !bytes.Equal(r.toClientOut.Bytes(), wantClient) {
			t.Fatalf("%+v: client got % x, want % x", clipboard, r.toClientOut.Bytes(), wantClient)
		}
		wantServer := join([]byte{rfbClientKeyEvent}, fill(7))
		if clipboard.Paste {
			wantServer = fromClient
		}
		if !bytes.Equal(r.toServer.Bytes(), wantServer) {
			t.Fatalf("%+v: server got % x, want % x", clipboard, r.toServer.Bytes(), wantServer)
		}
	}
}

// A CutText past 1 MiB is consumed even when allowed, at exactly the bound it
// passes, and a negative length ends the session.
func TestRFBCutTextBounds(t *testing.T) {
	both := clipboardAccess{Copy: true, Paste: true}
	atBound := cutText(rfbServerCutText, rfbMaxCutText, fill(rfbMaxCutText))
	r := newFilterRun(both, rfbV38, rfbSecNone, nil, join(atBound, []byte{rfbServerBell}))
	wantClosed(t, r.serverMessages())
	if r.toClientOut.Len() != len(atBound)+1 {
		t.Fatalf("client got %d bytes at the bound, want %d", r.toClientOut.Len(), len(atBound)+1)
	}
	over := cutText(rfbServerCutText, rfbMaxCutText+1, fill(rfbMaxCutText+1))
	r = newFilterRun(both, rfbV38, rfbSecNone, nil, join(over, []byte{rfbServerBell}))
	wantClosed(t, r.serverMessages())
	if !bytes.Equal(r.toClientOut.Bytes(), []byte{rfbServerBell}) {
		t.Fatalf("client got %d bytes of an oversize CutText", r.toClientOut.Len())
	}
	wantViolation(t, newFilterRun(both, rfbV38, rfbSecNone, nil, cutText(rfbServerCutText, -8, nil)).serverMessages())
	wantViolation(t, newFilterRun(both, rfbV38, rfbSecNone, cutText(rfbClientCutText, -8, nil), nil).clientMessages())
}

// A resume that narrows the clipboard applies at the next CutText.
func TestRFBCutTextFollowsTheCurrentAdmission(t *testing.T) {
	first := cutText(rfbServerCutText, 1, []byte("a"))
	r := newFilterRun(clipboardAccess{Copy: true}, rfbV38, rfbSecNone, nil, first)
	wantClosed(t, r.serverMessages())
	if !bytes.Equal(r.toClientOut.Bytes(), first) {
		t.Fatalf("client got % x before the narrowing", r.toClientOut.Bytes())
	}
	r.toClientOut.Reset()
	r.c.adm.Store(&connAdmission{admission: &admission{Kind: "vnc"}})
	r.toClient.r = bufio.NewReader(bytes.NewReader(first))
	wantClosed(t, r.serverMessages())
	if r.toClientOut.Len() != 0 {
		t.Fatalf("client got % x after the narrowing", r.toClientOut.Bytes())
	}
}

// SetPixelFormat passes before the first update request and takes effect for
// framing; after it the session ends, and updates in flight keep the format
// that framed them, so a CutText after one is still seen as a CutText.
func TestRFBSetPixelFormatRules(t *testing.T) {
	format := func(bits byte) []byte {
		return join([]byte{rfbClientSetPixelFormat}, fill(3), []byte{bits, bits, 0, 1}, be16(31), be16(31), be16(31), fill(6))
	}
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, format(16), nil)
	wantClosed(t, r.clientMessages())
	if r.pixelFormat.Load().bytes != 2 {
		t.Fatalf("the framing format has %d bytes per pixel, want 2", r.pixelFormat.Load().bytes)
	}

	request := join([]byte{rfbClientUpdateRequest}, fill(9))
	server := join(update(rect(2, 1, rfbEncRaw, fill(8))), cutText(rfbServerCutText, 2, []byte("no")), []byte{rfbServerBell})
	r = newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(request, format(8)), server)
	wantViolation(t, r.clientMessages())
	if err := r.toTarget.flush(); err != nil {
		t.Fatal(err)
	}
	if got := r.toServer.Bytes(); !bytes.Equal(got, request) {
		t.Fatalf("server got % x, want only the update request", got)
	}
	if r.pixelFormat.Load().bytes != 4 {
		t.Fatal("a refused SetPixelFormat changed the framing format")
	}
	wantClosed(t, r.serverMessages())
	want := join(update(rect(2, 1, rfbEncRaw, fill(8))), []byte{rfbServerBell})
	if !bytes.Equal(r.toClientOut.Bytes(), want) {
		t.Fatalf("client got % x, want % x", r.toClientOut.Bytes(), want)
	}

	offered := setEncodings(rfbEncContinuousUpdates)
	enable := join([]byte{rfbClientEnableContinuous}, fill(9))
	r = newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(offered, enable, format(8)), nil)
	wantViolation(t, r.clientMessages())
	if r.pixelFormat.Load().bytes != 4 {
		t.Fatal("a SetPixelFormat after EnableContinuousUpdates changed the framing format")
	}

	// A server may answer a SetEncodings with pixels, a cursor for one.
	r = newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, join(setEncodings(rfbEncCursor), format(8)), nil)
	wantViolation(t, r.clientMessages())
	if r.pixelFormat.Load().bytes != 4 {
		t.Fatal("a SetPixelFormat after SetEncodings changed the framing format")
	}

	wantViolation(t, newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, format(24), nil).clientMessages())
}

// A 24-bit format of 8-bit channels passes at byte-aligned shifts, which
// frames Tight pixels as 3 bytes, and is refused at any other shift.
func TestRFBSetPixelFormatShifts(t *testing.T) {
	format := func(red, green, blue byte) []byte {
		return join([]byte{rfbClientSetPixelFormat}, fill(3), []byte{32, 24, 0, 1}, be16(255), be16(255), be16(255), []byte{red, green, blue}, fill(3))
	}
	r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, format(0, 8, 16), nil)
	wantClosed(t, r.clientMessages())
	if r.pixelFormat.Load().tight != 3 {
		t.Fatalf("Tight pixels of %d bytes, want 3", r.pixelFormat.Load().tight)
	}
	for _, shifts := range [][3]byte{{1, 8, 16}, {0, 9, 16}, {0, 8, 17}} {
		r := newFilterRun(clipboardAccess{}, rfbV38, rfbSecNone, format(shifts[0], shifts[1], shifts[2]), nil)
		wantViolation(t, r.clientMessages())
	}
}

// A security type or VeNCrypt subtype outside the allowlist ends the
// connection before the choice reaches the target.
func TestRFBAllowlistBeforeTheTarget(t *testing.T) {
	seen := func(c net.Conn, rest chan<- []byte) {
		b, _ := io.ReadAll(c)
		rest <- b
	}
	t.Run("top level", func(t *testing.T) {
		for _, choice := range []byte{5, 18, 129} {
			rest := make(chan []byte, 1)
			script := rfbServerNoChoice("RFB 003.008\n", []byte{choice}, func(c net.Conn) error {
				seen(c, rest)
				return errors.New("done")
			})
			f, _ := keyFixture(t, script, &memKeys{})
			client := f.connect(t, f.vncOpts())
			ch, reqs, err := openDesktopChannel(client, chanVNC)
			if err != nil {
				t.Fatal(err)
			}
			if err := clientHandshake(ch, "RFB 003.008\n", choice); err != nil {
				t.Fatal(err)
			}
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
				t.Fatalf("type %d: end reason %q", choice, reason)
			}
			if b := <-rest; len(b) != 0 {
				t.Fatalf("type %d: the target read % x", choice, b)
			}
		}
	})
	t.Run("3.3 server choice", func(t *testing.T) {
		f, _ := keyFixture(t, rfbServer("RFB 003.003\n", nil, 5, func(net.Conn) error { return nil }), &memKeys{})
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		readFor(t, ch, "RFB 003.003\n")
		_, _ = io.WriteString(ch, "RFB 003.003\n")
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
			t.Fatalf("end reason %q", reason)
		}
		if rest := readAll(ch); len(rest) != 0 {
			t.Fatalf("%d bytes of a refused choice reached the client", len(rest))
		}
	})
	t.Run("vencrypt subtype", func(t *testing.T) {
		for _, sub := range []uint32{5, 19, 257, 258, 259, 260, 261, 262} {
			rest := make(chan []byte, 1)
			script := rfbServer("RFB 003.008\n", []byte{19}, 0, func(c net.Conn) error {
				if _, err := c.Write([]byte{0, 2}); err != nil {
					return err
				}
				if _, err := io.ReadFull(c, make([]byte, 2)); err != nil {
					return err
				}
				if _, err := c.Write(append([]byte{0, 1}, be32(sub)...)); err != nil {
					return err
				}
				seen(c, rest)
				return errors.New("done")
			})
			f, _ := keyFixture(t, script, &memKeys{})
			client := f.connect(t, f.vncOpts())
			ch, reqs, err := openDesktopChannel(client, chanVNC)
			if err != nil {
				t.Fatal(err)
			}
			if err := clientHandshake(ch, "RFB 003.008\n", 19); err != nil {
				t.Fatal(err)
			}
			readFor(t, ch, "\x00\x02")
			_, _ = ch.Write([]byte{0, 2})
			readFor(t, ch, string(append([]byte{0, 1}, be32(sub)...)))
			_, _ = ch.Write(be32(sub))
			if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
				t.Fatalf("subtype %d: end reason %q", sub, reason)
			}
			if b := <-rest; len(b) != 0 {
				t.Fatalf("subtype %d: the target read % x", sub, b)
			}
		}
	})
}

// rfbServerNoChoice is rfbServer that leaves the client's choice unread, so
// after sees whether it arrived.
func rfbServerNoChoice(version string, types []byte, after func(net.Conn) error) func(net.Conn) error {
	return func(c net.Conn) error {
		if _, err := io.WriteString(c, version); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, make([]byte, 12)); err != nil {
			return err
		}
		if _, err := c.Write(append([]byte{byte(len(types))}, types...)); err != nil {
			return err
		}
		return after(c)
	}
}

// A violation in either direction reaches the client as its end reason over
// the channel, which stays open for it, and closes the target.
func TestRFBViolationReachesTheClient(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ch.Write([]byte{99}); err != nil {
			t.Fatal(err)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
			t.Fatalf("end reason %q", reason)
		}
		target.waitClosed(t)
		waitClosed(t, client)
	})
	t.Run("server", func(t *testing.T) {
		target := newVNCTarget(t)
		f := desktopFixture(t, target.ln.Addr().String(), nil)
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openVNC(client)
		if err != nil {
			t.Fatal(err)
		}
		desktopPing(t, ch)
		if _, err := target.serverSide(t).Write([]byte{99}); err != nil {
			t.Fatal(err)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
			t.Fatalf("end reason %q", reason)
		}
		target.waitClosed(t)
		waitClosed(t, client)
	})
	t.Run("handshake", func(t *testing.T) {
		script := rfbServer("RFB 003.008\n", []byte{rfbSecTight}, 0, func(c net.Conn) error {
			_, err := c.Write(be32(rfbMaxTightTunnels + 1))
			return err
		})
		f, _ := keyFixture(t, script, &memKeys{})
		client := f.connect(t, f.vncOpts())
		ch, reqs, err := openDesktopChannel(client, chanVNC)
		if err != nil {
			t.Fatal(err)
		}
		if err := clientHandshake(ch, "RFB 003.008\n", rfbSecTight); err != nil {
			t.Fatal(err)
		}
		if reason := waitEndRequest(t, reqs); reason != CloseDesktopProtocolViolation {
			t.Fatalf("end reason %q", reason)
		}
		waitClosed(t, client)
	})
}

// A resumed connection applies the resume certificate's clipboard: a CutText
// its new certificate denies never reaches the client, and the session goes on.
func TestDesktopResumeNarrowsTheClipboard(t *testing.T) {
	clock := &manualClock{}
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), func(c *ServerConfig) { c.clock = clock })
	rc := f.connectResumableAs(t, f.vncOpts())
	ch, _, err := openVNC(rc.client)
	if err != nil {
		t.Fatal(err)
	}
	server := target.serverSide(t)
	allowed := cutText(rfbServerCutText, 2, []byte("ok"))
	if _, err := server.Write(allowed); err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, string(allowed))
	rc.cut(t)
	none := ""
	if err := rc.resume(t, func(o *certOpts) { o.kind, o.login, o.clipboard = "vnc", desktopPrincipal, &none }); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := server.Write(join(cutText(rfbServerCutText, 2, []byte("no")), []byte{rfbServerBell})); err != nil {
		t.Fatal(err)
	}
	readFor(t, ch, string([]byte{rfbServerBell}))
}

// A desktop certificate needs a valid clipboard option; another kind may not
// carry one.
func TestDesktopClipboardOptionRefusals(t *testing.T) {
	target := newVNCTarget(t)
	f := desktopFixture(t, target.ln.Addr().String(), nil)
	dial := func(o certOpts) error {
		signer, _ := f.mint(t, o)
		client, err := f.dial(t, o.serial, signer, nil)
		if err == nil {
			_ = client.Close()
		}
		return err
	}
	for name, edit := range map[string]func(*certOpts){
		"missing":       func(o *certOpts) { o.noClipboard = true },
		"another order": func(o *certOpts) { o.clipboard = new("paste,copy") },
		"unknown value": func(o *certOpts) { o.clipboard = new("all") },
	} {
		t.Run(name, func(t *testing.T) {
			o := f.vncOpts()
			edit(&o)
			if err := dial(o); err == nil {
				t.Fatal("certificate admitted")
			}
		})
	}
	for _, value := range []string{"", "copy", "paste", "copy,paste"} {
		o := f.vncOpts()
		o.clipboard = &value
		if err := dial(o); err != nil {
			t.Fatalf("clipboard %q refused: %v", value, err)
		}
	}
	terminal := newSSHFixture(t, nil)
	o := terminal.defaults()
	o.clipboard = new("copy")
	signer, _ := terminal.mint(t, o)
	if _, err := terminal.dial(t, o.serial, signer, nil); err == nil {
		t.Fatal("a terminal certificate with a clipboard option was admitted")
	}
}
