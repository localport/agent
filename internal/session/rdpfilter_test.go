//go:build linux || darwin

package session

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// rdpGoldens are the PDUs of testdata/rdpfilter.golden, encoded by IronRDP
// (testdata/rdpfilter), in file order.
var rdpGoldens = sync.OnceValues(func() (map[string][]byte, []string) {
	b, err := os.ReadFile("testdata/rdpfilter.golden")
	if err != nil {
		panic(err)
	}
	m, order := map[string][]byte{}, []string(nil)
	for line := range strings.Lines(string(b)) {
		name, h, ok := strings.Cut(strings.TrimSpace(line), " ")
		pdu, err := hex.DecodeString(h)
		if !ok || err != nil {
			panic("bad golden line " + name)
		}
		m[name], order = pdu, append(order, name)
	}
	return m, order
})

func rdpPDU(t *testing.T, name string) []byte {
	t.Helper()
	m, _ := rdpGoldens()
	pdu, ok := m[name]
	if !ok {
		t.Fatalf("no golden %q", name)
	}
	return bytes.Clone(pdu)
}

// rdpStep is one write of a recorded session.
type rdpStep struct {
	from rdpSide
	pdu  []byte
}

// rdpTranscript is the recorded session variant, from the Connect Initial
// to the end of the connection finalization.
func rdpTranscript(t *testing.T, variant string) []rdpStep {
	t.Helper()
	m, order := rdpGoldens()
	var steps []rdpStep
	for _, name := range order {
		if rest, ok := strings.CutPrefix(name, variant+"."); ok {
			from := rdpServer
			if strings.HasSuffix(rest, ".c") {
				from = rdpClient
			}
			steps = append(steps, rdpStep{from, m[name]})
		}
	}
	if len(steps) == 0 {
		t.Fatalf("no session %q", variant)
	}
	return steps
}

// pipeReader collects what the agent writes toward one side.
type pipeReader struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  []byte
	err  error
}

func newPipeReader(c net.Conn) *pipeReader {
	p := &pipeReader{}
	p.cond = sync.NewCond(&p.mu)
	go func() {
		b := make([]byte, 64<<10)
		for {
			n, err := c.Read(b)
			p.mu.Lock()
			p.buf = append(p.buf, b[:n]...)
			if err != nil {
				p.err = err
			}
			p.cond.Broadcast()
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

// next returns the next n bytes, or fewer when the side closed or 5 s
// passed.
func (p *pipeReader) next(n int) []byte {
	deadline := time.AfterFunc(5*time.Second, func() {
		p.mu.Lock()
		p.err = errTimeout
		p.cond.Broadcast()
		p.mu.Unlock()
	})
	defer deadline.Stop()
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) < n && p.err == nil {
		p.cond.Wait()
	}
	k := min(n, len(p.buf))
	out := bytes.Clone(p.buf[:k])
	p.buf = p.buf[k:]
	return out
}

type timeoutError struct{}

func (timeoutError) Error() string { return "timeout" }

var errTimeout error = timeoutError{}

// rdpRun is an rdpFilter between the test, playing the client and the
// server over pipes, with both pumps running.
type rdpRun struct {
	t     *testing.T
	f     *rdpFilter
	write [2]net.Conn // the test's end toward the agent, per side it plays
	agent [2]net.Conn // the agent's end toward each side
	got   [2]*pipeReader
	ended chan string
	// clipReady: the cliprdr capability exchange ran.
	clipReady bool
}

func newRDPRun(t *testing.T, protocol uint32, access clipboardAccess, edit ...func(*rdpFilter)) *rdpRun {
	t.Helper()
	c := &conn{s: NewServer(ServerConfig{}), failed: make(chan string, 1), channels: map[*channel]struct{}{}}
	c.adm.Store(&connAdmission{admission: &admission{Kind: "rdp", Clipboard: access}})
	agentClient, testClient := net.Pipe()
	agentServer, testServer := net.Pipe()
	r := &rdpRun{t: t, ended: make(chan string, 2)}
	r.f = newRDPFilterOver(c, protocol, bufio.NewReader(agentClient), agentClient, agentServer)
	for _, e := range edit {
		e(r.f)
	}
	r.write[rdpClient], r.write[rdpServer] = testClient, testServer
	r.agent[rdpClient], r.agent[rdpServer] = agentClient, agentServer
	r.got[rdpClient], r.got[rdpServer] = newPipeReader(testClient), newPipeReader(testServer)
	stop := func() { _ = agentClient.Close(); _ = agentServer.Close() }
	go func() { r.ended <- r.f.pumpToTarget(); stop() }()
	go func() { r.ended <- r.f.pumpToClient(); stop() }()
	t.Cleanup(func() { stop(); _ = testClient.Close(); _ = testServer.Close() })
	return r
}

// send writes b as side from; a refused write ends the pump, so its error is
// the end's and goes unchecked.
func (r *rdpRun) send(from rdpSide, b []byte) {
	_, _ = r.write[from].Write(b)
}

// expect fails unless the next bytes toward side are want.
func (r *rdpRun) expect(to rdpSide, want []byte) {
	r.t.Helper()
	if got := r.got[to].next(len(want)); !bytes.Equal(got, want) {
		r.t.Fatalf("%s got\n%x\nwant\n%x", to.name(), got, want)
	}
}

// pass sends b from side and expects it unchanged on the other side.
func (r *rdpRun) pass(from rdpSide, b []byte) {
	r.t.Helper()
	r.send(from, b)
	r.expect(from.other(), b)
}

// marker passes a PDU that changes no filter state, proving nothing else
// reached the other side before it.
func (r *rdpRun) marker(from rdpSide) {
	r.t.Helper()
	if from == rdpClient {
		r.pass(rdpClient, rdpPDU(r.t, "c.fastpath_sync"))
		return
	}
	steps := rdpTranscript(r.t, "base")
	r.pass(rdpServer, steps[len(steps)-1].pdu)
}

// wantEnd fails unless the filter ends with reason.
func (r *rdpRun) wantEnd(reason string) {
	r.t.Helper()
	select {
	case got := <-r.ended:
		if got != reason {
			r.t.Fatalf("ended %q, want %q", got, reason)
		}
	case <-time.After(5 * time.Second):
		r.t.Fatalf("no end, want %q", reason)
	}
}

// connect replays a recorded session through the filter.
func (r *rdpRun) connect(variant string) {
	r.t.Helper()
	for _, s := range rdpTranscript(r.t, variant) {
		r.pass(s.from, s.pdu)
	}
}

// svc encodes payload as the virtual channel message side from sends on ch,
// at the negotiated chunk size.
func (r *rdpRun) svc(from rdpSide, ch rdpChannel, payload []byte, flags uint32) []byte {
	r.f.mu.Lock()
	defer r.f.mu.Unlock()
	return r.f.encode(nil, rdpFrame{to: from.other(), channel: ch, payload: payload, flags: flags})
}

// der encodes one DER element.
func der(tag byte, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	switch n := len(body); {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, body...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, body...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, body...)
	}
}

// tsRequest is a TSRequest (MS-CSSP 2.2.1) with version 6 and the given
// fields, each [n] OCTET STRING.
func tsRequest(fields map[byte][]byte) []byte {
	parts := [][]byte{der(0xa0, der(0x02, []byte{6}))}
	for n := byte(1); n <= 6; n++ {
		if v, ok := fields[n]; ok {
			parts = append(parts, der(0xa0+n, der(0x04, v)))
		}
	}
	return der(0x30, parts...)
}

var (
	allClipboard = clipboardAccess{Copy: true, Paste: true}
	tsNego       = tsRequest(map[byte][]byte{1: []byte("negotiate token")})
	tsChallenge  = tsRequest(map[byte][]byte{1: []byte("challenge token")})
	tsAuth       = tsRequest(map[byte][]byte{2: []byte("credentials"), 3: []byte("pub key auth")})
)

// credssp runs a CredSSP exchange for protocol through the filter.
func (r *rdpRun) credssp(protocol uint32) {
	r.t.Helper()
	r.pass(rdpClient, tsNego)
	r.pass(rdpServer, tsChallenge)
	r.pass(rdpClient, tsAuth)
	if protocol == rdpProtocolHybridEx {
		r.pass(rdpServer, []byte{0, 0, 0, 0})
	}
}

// Each security path reaches the Connect Initial and carries a recorded
// IronRDP session unchanged.
func TestRDPFilterSecurityPaths(t *testing.T) {
	for name, protocol := range map[string]uint32{"ssl": rdpProtocolSSL, "hybrid": rdpProtocolHybrid, "hybrid_ex": rdpProtocolHybridEx} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, protocol, allClipboard)
			if protocol != rdpProtocolSSL {
				r.credssp(protocol)
			}
			r.connect("base")
			r.marker(rdpClient)
			r.marker(rdpServer)
		})
	}
}

// A TSRequest and a Connect Initial naming rdpdr in one write: the filter
// splits them at the DER boundary and the Connect Initial ends the
// connection; the target never sees it.
func TestRDPFilterGluedConnectInitial(t *testing.T) {
	r := newRDPRun(t, rdpProtocolHybrid, allClipboard)
	r.pass(rdpClient, tsNego)
	r.pass(rdpServer, tsChallenge)
	r.send(rdpClient, append(bytes.Clone(tsAuth), rdpTranscript(t, "rdpdr")[0].pdu...))
	r.wantEnd(CloseDesktopChannelRefused)
	// The TSRequest may still be in the sink's buffer at the end.
	if got := r.got[rdpServer].next(len(tsAuth) + 1); len(got) != 0 && !bytes.Equal(got, tsAuth) {
		t.Fatalf("the target got %x", got)
	}
}

func TestRDPFilterFramingRefusals(t *testing.T) {
	connectInitial := rdpTranscript(t, "base")[0].pdu
	noEOT := bytes.Clone(connectInitial)
	noEOT[6] = 0
	for name, tc := range map[string]struct {
		protocol uint32
		credssp  func(*rdpRun)
		send     []byte
	}{
		"TPDU without EOT":           {protocol: rdpProtocolSSL, send: noEOT},
		"fast-path before connect":   {protocol: rdpProtocolSSL, send: rdpPDU(t, "c.fastpath_sync")},
		"non-TPKT after the CredSSP": {protocol: rdpProtocolHybrid, credssp: func(r *rdpRun) { r.credssp(rdpProtocolHybrid) }, send: tsNego},
		"not a TSRequest":            {protocol: rdpProtocolHybrid, send: connectInitial},
		"indefinite TSRequest":       {protocol: rdpProtocolHybrid, send: []byte{0x30, 0x80, 0, 0}},
		"TSRequest field tag":        {protocol: rdpProtocolHybrid, send: der(0x30, der(0x04, []byte("x")))},
		"TSRequest too long":         {protocol: rdpProtocolHybrid, send: []byte{0x30, 0x82, 0xff, 0xff}},
		"TPKT too long":              {protocol: rdpProtocolSSL, send: []byte{0x03, 0x00, 0x40, 0x05}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, tc.protocol, allClipboard)
			if tc.credssp != nil {
				tc.credssp(r)
			}
			r.send(rdpClient, tc.send)
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}

// Under HYBRID_EX the server's Early User Authorization Result follows the
// client's authInfo; a server byte that is neither ends the connection.
func TestRDPFilterServerCredSSPRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		protocol uint32
		auth     bool
		send     []byte
	}{
		"TPKT before authInfo":    {protocol: rdpProtocolHybrid, send: rdpTranscript(t, "base")[1].pdu},
		"bad EUAR":                {protocol: rdpProtocolHybridEx, auth: true, send: []byte{1, 0, 0, 0}},
		"stray byte under HYBRID": {protocol: rdpProtocolHybrid, auth: true, send: []byte{0x00}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, tc.protocol, allClipboard)
			r.pass(rdpClient, tsNego)
			if tc.auth {
				r.pass(rdpClient, tsAuth)
			}
			r.send(rdpServer, tc.send)
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}

// The static channels a client may ask for: drdynvc always, cliprdr only
// when a clipboard direction is allowed; any other ends the connection
// before the target sees the Connect Initial.
func TestRDPFilterStaticChannels(t *testing.T) {
	copyOnly, pasteOnly := clipboardAccess{Copy: true}, clipboardAccess{Paste: true}
	for name, tc := range map[string]struct {
		variant string
		access  clipboardAccess
		refused bool
	}{
		"both":                      {variant: "base", access: allClipboard},
		"copy only":                 {variant: "base", access: copyOnly},
		"paste only":                {variant: "base", access: pasteOnly},
		"drdynvc without clipboard": {variant: "drdynvc"},
		"none":                      {variant: "none"},
		"cliprdr alone":             {variant: "cliprdr", access: copyOnly},
		"cliprdr without clipboard": {variant: "base", refused: true},
		"rdpdr":                     {variant: "rdpdr", access: allClipboard, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, tc.access)
			if !tc.refused {
				r.connect(tc.variant)
				r.marker(rdpClient)
				return
			}
			r.send(rdpClient, rdpTranscript(t, tc.variant)[0].pdu)
			r.wantEnd(CloseDesktopChannelRefused)
			if got := r.got[rdpServer].next(1); len(got) != 0 {
				t.Fatalf("the target got %x", got)
			}
		})
	}
}

// The recorded Connect Response assigns io 1003, cliprdr 1004, drdynvc 1005
// and message 1006, and the Attach User Confirm user 1002. A zero or
// repeated id in either ends the connection before the client sees it.
func TestRDPFilterChannelIDs(t *testing.T) {
	const scNet, scMsg = "030c0c00eb030200ec03ed03", "040c0600ee03"
	for name, tc := range map[string]struct {
		net, msg string
		user     string // Attach User Confirm initiator, hex
	}{
		"io zero":                {net: "030c0c0000000200ec03ed03"},
		"channel zero":           {net: "030c0c00eb0302000000ed03"},
		"channel equals io":      {net: "030c0c00eb030200eb03ed03"},
		"channels equal":         {net: "030c0c00eb030200ec03ec03"},
		"message zero":           {msg: "040c06000000"},
		"message equals io":      {msg: "040c0600eb03"},
		"message equals channel": {msg: "040c0600ed03"},
		"user equals io":         {user: "0002"},
		"user equals channel":    {user: "0003"},
		"user equals message":    {user: "0005"},
		"user zero":              {user: "fc17"},
	} {
		t.Run(name, func(t *testing.T) {
			steps := rdpTranscript(t, "base")
			cr := hex.EncodeToString(steps[1].pdu)
			if tc.net != "" {
				cr = strings.Replace(cr, scNet, tc.net, 1)
			}
			if tc.msg != "" {
				cr = strings.Replace(cr, scMsg, tc.msg, 1)
			}
			response, _ := hex.DecodeString(cr)
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.pass(rdpClient, steps[0].pdu)
			if tc.user == "" {
				r.send(rdpServer, response)
				r.wantEnd(CloseDesktopProtocolViolation)
				if got := r.got[rdpClient].next(1); len(got) != 0 {
					t.Fatalf("the client got %x", got)
				}
				return
			}
			r.pass(rdpServer, response)
			for _, s := range steps[2:4] {
				r.pass(s.from, s.pdu)
			}
			confirm := bytes.Clone(steps[4].pdu)
			user, _ := hex.DecodeString(tc.user)
			copy(confirm[len(confirm)-2:], user)
			r.send(rdpServer, confirm)
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}

// Channel names compare case-insensitively, and each name other than
// drdynvc and an allowed cliprdr is refused: the recorded Connect Initial
// with one CS_NET name replaced by another of the same length.
func TestRDPFilterChannelNames(t *testing.T) {
	for name, tc := range map[string]struct {
		from, to string
		access   clipboardAccess
		refused  bool
	}{
		"CLIPRDR with a direction":    {from: "cliprdr", to: "CLIPRDR", access: clipboardAccess{Copy: true}},
		"CLIPRDR without a direction": {from: "cliprdr", to: "CLIPRDR", refused: true},
		"DRDYNVC":                     {from: "drdynvc", to: "DRDYNVC", access: clipboardAccess{Paste: true}},
		"rdpsnd":                      {from: "cliprdr", to: "rdpsnd\x00", access: allClipboard, refused: true},
		"rail":                        {from: "drdynvc", to: "rail\x00\x00\x00", access: allClipboard, refused: true},
		"encomsp":                     {from: "drdynvc", to: "encomsp", access: allClipboard, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			steps := rdpTranscript(t, "base")
			ci := bytes.Clone(steps[0].pdu)
			i := bytes.Index(ci, []byte(tc.from+"\x00"))
			if i < 0 || len(tc.to) != len(tc.from) {
				t.Fatalf("no CS_NET name %q", tc.from)
			}
			copy(ci[i:], tc.to)
			r := newRDPRun(t, rdpProtocolSSL, tc.access)
			r.send(rdpClient, ci)
			if tc.refused {
				r.wantEnd(CloseDesktopChannelRefused)
				return
			}
			r.expect(rdpServer, ci)
			for _, s := range steps[1:] {
				r.pass(s.from, s.pdu)
			}
			r.marker(rdpClient)
		})
	}
}

// The IronRDP client the web page runs asks for no compression: its Client
// Info PDU sets no INFO_COMPRESSION or compression type (MS-RDPBCGR
// 2.2.1.11.1.1) and its Virtual Channel Capability Set is VCCAPS_NO_COMPR
// (2.2.7.1.10), as recorded from ironrdp-connector, whose code the fork
// carries unchanged.
func TestRDPClientAsksNoCompression(t *testing.T) {
	steps := rdpTranscript(t, "base")
	info := steps[5].pdu // Client Info: TPKT 4, X.224 3, MCS 6 and a 2-byte PER length
	data := info[15:]
	if binary.LittleEndian.Uint16(data)&0x0040 == 0 {
		t.Fatal("the recorded PDU is not the Client Info PDU")
	}
	if flags := binary.LittleEndian.Uint32(data[8:]); flags&(0x80|0x1e00) != 0 {
		t.Fatalf("Client Info flags %#x ask for compression", flags)
	}
	confirm := steps[8].pdu
	i := bytes.Index(confirm, []byte{capsTypeVirtualChannel, 0x00, 0x0c, 0x00})
	if i < 0 {
		t.Fatal("no Virtual Channel Capability Set in the Confirm Active")
	}
	if flags := binary.LittleEndian.Uint32(confirm[i+4:]); flags != 0 {
		t.Fatalf("Virtual Channel Capability Set flags %#x", flags)
	}
}

// Send Data on a channel the server did not assign, or from another
// initiator, ends the connection.
func TestRDPFilterUnknownChannel(t *testing.T) {
	m, _ := rdpGoldens()
	ids := m["ids"]
	cliprdr := binary.BigEndian.Uint16(ids[2:])
	for name, edit := range map[string]func([]byte){
		"channel":   func(b []byte) { binary.BigEndian.PutUint16(b[10:], cliprdr+40) },
		"initiator": func(b []byte) { binary.BigEndian.PutUint16(b[8:], 7) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			pdu := rdpPDU(t, "c.caps")
			edit(pdu)
			r.send(rdpClient, pdu)
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}

// A compressed chunk on cliprdr or drdynvc ends the connection.
func TestRDPFilterCompressedChunk(t *testing.T) {
	for _, name := range []string{"s.caps", "s.dvc_caps_v2"} {
		for flag, v := range map[string]uint32{"compressed": channelPacketCompressed, "type": 0x00010000} {
			t.Run(name+" "+flag, func(t *testing.T) {
				r := newRDPRun(t, rdpProtocolSSL, allClipboard)
				r.connect("base")
				pdu := rdpPDU(t, name)
				// TPKT 4, X.224 3, MCS 6, PER length 1, then CHANNEL_PDU_HEADER.
				binary.LittleEndian.PutUint32(pdu[18:], binary.LittleEndian.Uint32(pdu[18:])|v)
				r.send(rdpServer, pdu)
				r.wantEnd(CloseDesktopProtocolViolation)
			})
		}
	}
}

// Without VCChunkSize on both sides the chunk size is 1,600: a larger
// incoming chunk ends the connection, and the agent writes 1,600-byte
// chunks. With the server's 4,096 the agent writes and accepts 4,096.
func TestRDPFilterChunkSize(t *testing.T) {
	big := rdpPDU(t, "c.resp_4000_chunk4096")
	t.Run("1600 refuses a larger chunk", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		pasteRequested(r)
		r.send(rdpClient, big)
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("4096 negotiated", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("chunk")
		pasteRequested(r)
		r.pass(rdpClient, big)
		copyRequested(r)
		r.send(rdpServer, rdpPDU(t, "s.resp_4000"))
		r.expect(rdpClient, oneChunk(t, r, rdpClient, rdpPDU(t, "s.resp_4000")))
	})
	t.Run("reactivation renegotiates", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		chunk := rdpTranscript(t, "chunk")
		r.pass(rdpServer, rdpPDU(t, "s.deactivate_all"))
		r.pass(chunk[7].from, chunk[7].pdu) // Demand Active, VCChunkSize 4096
		r.pass(chunk[8].from, chunk[8].pdu) // Confirm Active
		pasteRequested(r)
		r.pass(rdpClient, big)
	})
	t.Run("a chunk at the old size during a reactivation", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("chunk")
		pasteRequested(r)
		base := rdpTranscript(t, "base")
		r.pass(rdpServer, rdpPDU(t, "s.deactivate_all"))
		r.pass(base[7].from, base[7].pdu) // Demand Active without VCChunkSize
		// Sent at 4096 before the client saw the new Demand Active: it passes,
		// written to the server at 1600, which both sizes allow.
		r.send(rdpClient, big)
		r.expect(rdpServer, rdpPDU(t, "c.resp_4000"))
		r.pass(base[8].from, base[8].pdu) // Confirm Active: 1600 from now on
		r.pass(rdpServer, rdpPDU(t, "s.req_unicode"))
		r.send(rdpClient, big)
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("writes at the smaller size while a reactivation raises it", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		copyRequested(r)
		chunk := rdpTranscript(t, "chunk")
		r.pass(rdpServer, rdpPDU(t, "s.deactivate_all"))
		r.pass(chunk[7].from, chunk[7].pdu) // Demand Active, VCChunkSize 4096
		// The client has not confirmed 4096 yet: the agent writes at 1600.
		r.pass(rdpServer, rdpPDU(t, "s.resp_4000"))
	})
	t.Run("server VCChunkSize out of range", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		steps := rdpTranscript(t, "chunk")
		for _, s := range steps[:7] {
			r.pass(s.from, s.pdu)
		}
		demand := bytes.Clone(steps[7].pdu)
		i := bytes.Index(demand, []byte{0x14, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00})
		if i < 0 {
			t.Fatal("no Virtual Channel Capability Set of 4096 in the Demand Active")
		}
		binary.LittleEndian.PutUint32(demand[i+8:], 100)
		r.send(rdpServer, demand)
		r.wantEnd(CloseDesktopProtocolViolation)
	})
}

// oneChunk re-encodes a recorded message as one chunk toward side.
func oneChunk(t *testing.T, r *rdpRun, to rdpSide, recorded []byte) []byte {
	t.Helper()
	payload := svcPayload(t, recorded)
	return r.svc(to.other(), rdpCliprdr, payload, 0)
}

// firstTPKT is the first PDU of b.
func firstTPKT(b []byte) []byte { return b[:binary.BigEndian.Uint16(b[2:])] }

// svcPayload reassembles the virtual channel message of recorded chunks.
func svcPayload(t *testing.T, b []byte) []byte {
	t.Helper()
	var out []byte
	for len(b) > 0 {
		n := int(binary.BigEndian.Uint16(b[2:]))
		mcs := b[7:n]
		_, data, err := perLength(mcs[6:])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data[8:]...)
		b = b[n:]
	}
	return out
}

// Chunks reassemble across three; a chunk outside its message, a message
// past its length or short of it, and a message past the bound end.
func TestRDPFilterReassembly(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	copyRequested(r)
	r.pass(rdpServer, rdpPDU(t, "s.resp_4000"))

	resp := rdpPDU(t, "s.resp_4000")
	first := int(binary.BigEndian.Uint16(resp[2:]))
	for name, pdu := range map[string][]byte{
		"middle without first": resp[first:],
		"first twice":          append(bytes.Clone(resp[:first]), resp[:first]...),
		"over the bound":       firstTPKT(r.svc(rdpServer, rdpCliprdr, cliprdrPDU(cbFormatList, 0, make([]byte, rdpMaxClipPDU)), 0)),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRDPRun(t, rdpProtocolSSL, allClipboard)
			r.connect("base")
			copyRequested(r)
			r.send(rdpServer, pdu)
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
}

// Dynamic channels: only display control opens; any other create is
// answered STATUS_NOT_FOUND and never reaches the client; data on a channel
// not open, compressed data, Soft-Sync and a version-3 caps answer end.
func TestRDPFilterDynamicChannels(t *testing.T) {
	open := func(t *testing.T) *rdpRun {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		r.pass(rdpServer, rdpPDU(t, "s.dvc_caps_v3"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_caps_rsp_v2"))
		return r
	}
	t.Run("display control", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
		r.pass(rdpServer, rdpPDU(t, "s.dvc_data"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_data"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_data_first"))
		r.pass(rdpServer, rdpPDU(t, "s.dvc_close"))
		r.send(rdpServer, rdpPDU(t, "s.dvc_data"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("refused create", func(t *testing.T) {
		r := open(t)
		r.send(rdpServer, rdpPDU(t, "s.dvc_create_gfx"))
		r.expect(rdpServer, rdpPDU(t, "c.dvc_create_gfx_not_found"))
		r.marker(rdpServer)
		// Data the server sent before it read the refusal is dropped, as
		// IronRDP's client drops it for a channel it declined.
		r.send(rdpServer, rdpPDU(t, "s.dvc_data_gfx"))
		r.marker(rdpServer)
		r.send(rdpClient, rdpPDU(t, "c.dvc_data_gfx"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("failed create stays closed", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_create_fail"))
		r.send(rdpClient, rdpPDU(t, "c.dvc_data"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	for name, tc := range map[string]struct {
		from rdpSide
		pdu  string
	}{
		"client data not open":      {rdpClient, "c.dvc_data_gfx"},
		"server data not open":      {rdpServer, "s.dvc_data_gfx"},
		"unsolicited create answer": {rdpClient, "c.dvc_create_gfx_ok"},
		"server compressed":         {rdpServer, "s.dvc_data_compressed"},
		"client compressed":         {rdpClient, "c.dvc_data_compressed"},
		"soft sync":                 {rdpServer, "s.dvc_soft_sync"},
	} {
		t.Run(name, func(t *testing.T) {
			r := open(t)
			if strings.Contains(tc.pdu, "compressed") {
				r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
				r.pass(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
			}
			r.send(tc.from, rdpPDU(t, tc.pdu))
			r.wantEnd(CloseDesktopProtocolViolation)
		})
	}
	t.Run("version 3 answer", func(t *testing.T) {
		r := newRDPRun(t, rdpProtocolSSL, allClipboard)
		r.connect("base")
		r.pass(rdpServer, rdpPDU(t, "s.dvc_caps_v3"))
		r.send(rdpClient, rdpPDU(t, "c.dvc_caps_rsp_v3"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("server close and the client's answer", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
		r.pass(rdpServer, rdpPDU(t, "s.dvc_close"))
		// Sent before the client saw the Close: dropped, not a violation.
		r.send(rdpClient, rdpPDU(t, "c.dvc_data"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_close"))
		r.send(rdpClient, rdpPDU(t, "c.dvc_close"))
		r.marker(rdpClient)
		r.send(rdpClient, rdpPDU(t, "c.dvc_data"))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("server close of a pending channel", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpServer, rdpPDU(t, "s.dvc_close"))
		// IronRDP answered the Create before it read the Close.
		r.send(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_close"))
		r.marker(rdpClient)
	})
	t.Run("client close", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_close"))
		// Sent before the server saw the Close.
		r.send(rdpServer, rdpPDU(t, "s.dvc_data"))
		r.marker(rdpServer)
		// The id is free again for a new channel.
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
	})
	t.Run("data first shorter than its data", func(t *testing.T) {
		r := open(t)
		r.pass(rdpServer, rdpPDU(t, "s.dvc_create_display"))
		r.pass(rdpClient, rdpPDU(t, "c.dvc_create_ok"))
		// Data First: cmd 2, Len form 1 (two bytes), channel 3, length 10, 20 bytes.
		pdu := append([]byte{dvcDataFirst<<4 | 1<<2, 3, 10, 0}, make([]byte, 20)...)
		r.send(rdpClient, r.svc(rdpClient, rdpDrdynvc, pdu, 0))
		r.wantEnd(CloseDesktopProtocolViolation)
	})
	t.Run("close of a channel not open is dropped", func(t *testing.T) {
		r := open(t)
		r.send(rdpServer, rdpPDU(t, "s.dvc_close_gfx"))
		r.marker(rdpServer)
	})
}

// gateWriter blocks its first write of more than gate bytes after writing
// half of it, until release, and records whether another write ran inside.
type gateWriter struct {
	mu      sync.Mutex
	gate    int
	entered chan struct{}
	release chan struct{}
	inside  bool
	overlap bool
	w       net.Conn
}

func (g *gateWriter) Write(b []byte) (int, error) {
	g.mu.Lock()
	if g.inside {
		g.overlap = true
	}
	gated := g.gate > 0 && len(b) > g.gate
	if gated {
		g.gate, g.inside = 0, true
	}
	g.mu.Unlock()
	if !gated {
		return g.w.Write(b)
	}
	n, err := g.w.Write(b[:len(b)/2])
	close(g.entered)
	<-g.release
	if err == nil {
		var m int
		m, err = g.w.Write(b[len(b)/2:])
		n += m
	}
	g.mu.Lock()
	g.inside = false
	g.mu.Unlock()
	return n, err
}

// An agent RESPONSE_FAIL decided while the server pump writes a forwarded
// response toward the client waits for that PDU: the client sees whole PDUs.
func TestRDPFilterSinkSerializesDecisions(t *testing.T) {
	r := newRDPRun(t, rdpProtocolSSL, allClipboard)
	r.connect("base")
	copyRequested(r)
	gate := &gateWriter{gate: 2000, entered: make(chan struct{}), release: make(chan struct{})}
	deciding := make(chan struct{}, 1)
	r.f.mu.Lock()
	sink := r.f.sinks[rdpClient]
	r.f.beforeSinks = func() {
		select {
		case deciding <- struct{}{}:
		default:
		}
	}
	r.f.mu.Unlock()
	sink.mu.Lock()
	_ = sink.w.Flush()
	gate.w = r.agent[rdpClient]
	sink.w.Reset(gate)
	sink.mu.Unlock()

	// The response is forwarded as three chunks in one sink write.
	resp := rdpPDU(t, "s.resp_4000")
	go r.send(rdpServer, resp)
	<-gate.entered
	// A request for a format not listed: the client pump answers it.
	go r.send(rdpClient, rdpPDU(t, "c.req_html"))
	<-deciding
	// Release the forward once the decision either waits for the sink lock
	// or, without the lock, has written inside the gated write.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		gate.mu.Lock()
		overlap := gate.overlap
		gate.mu.Unlock()
		if overlap || sink.waiting.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the decision neither waited for the sink nor wrote")
		}
	}
	close(gate.release)
	r.expect(rdpClient, resp)
	r.expect(rdpClient, rdpPDU(t, "s.resp_fail"))
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.overlap {
		t.Fatal("a decision wrote inside a forwarded PDU")
	}
}
