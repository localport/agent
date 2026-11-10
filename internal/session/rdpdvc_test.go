//go:build linux || darwin

package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

// DVC PDUs on channel 3 (one-byte id), as MS-RDPEDYC 2.2 lays them out.
var (
	dvcCreateDisplay = append([]byte{dvcCreate << 4, 3}, dvcDisplayControl+"\x00"...)
	dvcCreateOther   = append([]byte{dvcCreate << 4, 3}, "Microsoft::Windows::RDS::Graphics\x00"...)
	dvcCreateOK      = binary.LittleEndian.AppendUint32([]byte{dvcCreate << 4, 3}, 0)
	dvcCreateFail    = binary.LittleEndian.AppendUint32([]byte{dvcCreate << 4, 3}, dvcNotFound)
	dvcDataPDU       = []byte{dvcData << 4, 3, 'x'}
	dvcClosePDU      = []byte{dvcClose << 4, 3}
)

type dvcOutcome uint8

const (
	dvcForward dvcOutcome = iota + 1
	dvcDrop
	dvcAnswer
	dvcRefuse
)

func (o dvcOutcome) String() string {
	return [...]string{"", "forward", "drop", "answer", "violation"}[o]
}

// dvcReach drives a fresh state machine's channel 3 to st.
func dvcReach(t *testing.T, st dvcState) *rdpDVC {
	t.Helper()
	s := &rdpDVC{}
	s.init()
	steps := map[dvcState][]struct {
		from rdpSide
		pdu  []byte
	}{
		dvcPending:       {{rdpServer, dvcCreateDisplay}},
		dvcOpen:          {{rdpServer, dvcCreateDisplay}, {rdpClient, dvcCreateOK}},
		dvcServerClosing: {{rdpServer, dvcCreateDisplay}, {rdpClient, dvcCreateOK}, {rdpServer, dvcClosePDU}},
		dvcClientClosed:  {{rdpServer, dvcCreateDisplay}, {rdpClient, dvcCreateOK}, {rdpClient, dvcClosePDU}},
	}[st]
	for _, step := range steps {
		if _, err := s.decide(step.from, step.pdu); err != nil {
			t.Fatal(err)
		}
	}
	if s.states[3] != st {
		t.Fatalf("reached %d, want %d", s.states[3], st)
	}
	return s
}

// Every state, every PDU from each side: the outcome and the next state of
// the table on rdpDVC.
func TestRDPDVCStateTable(t *testing.T) {
	type pdu struct {
		name string
		from rdpSide
		b    []byte
	}
	pdus := []pdu{
		{"server create display", rdpServer, dvcCreateDisplay},
		{"server create other", rdpServer, dvcCreateOther},
		{"server data", rdpServer, dvcDataPDU},
		{"server close", rdpServer, dvcClosePDU},
		{"client create ok", rdpClient, dvcCreateOK},
		{"client create fail", rdpClient, dvcCreateFail},
		{"client data", rdpClient, dvcDataPDU},
		{"client close", rdpClient, dvcClosePDU},
	}
	type row struct {
		out  dvcOutcome
		next dvcState
	}
	f, d, a, v := dvcForward, dvcDrop, dvcAnswer, dvcRefuse
	none, pend, open, sc, cc := dvcNone, dvcPending, dvcOpen, dvcServerClosing, dvcClientClosed
	table := map[dvcState][]row{
		none: {{f, pend}, {a, cc}, {v, none}, {d, none}, {v, none}, {v, none}, {v, none}, {d, none}},
		pend: {{v, pend}, {v, pend}, {v, pend}, {f, sc}, {f, open}, {f, cc}, {v, pend}, {d, pend}},
		open: {{v, open}, {v, open}, {f, open}, {f, sc}, {v, open}, {v, open}, {f, open}, {f, cc}},
		sc:   {{v, sc}, {v, sc}, {v, sc}, {d, sc}, {d, sc}, {d, none}, {d, sc}, {f, none}},
		cc:   {{f, pend}, {a, cc}, {d, cc}, {d, cc}, {v, cc}, {v, cc}, {v, cc}, {d, cc}},
	}
	for st, rows := range table {
		for i, p := range pdus {
			want := rows[i]
			t.Run(fmt.Sprintf("state %d %s", st, p.name), func(t *testing.T) {
				s := dvcReach(t, st)
				frames, err := s.decide(p.from, p.b)
				got := dvcForward
				switch {
				case errors.Is(err, errRDPViolation):
					got = dvcRefuse
				case err != nil:
					t.Fatal(err)
				case len(frames) == 0:
					got = dvcDrop
				case frames[0].to == p.from:
					got = dvcAnswer
				}
				if got != want.out {
					t.Fatalf("outcome %v, want %v", got, want.out)
				}
				if got != dvcRefuse && s.states[3] != want.next {
					t.Fatalf("next state %d, want %d", s.states[3], want.next)
				}
			})
		}
	}
}

// dvcOpenAndClose opens channel id and has side by close it.
func dvcOpenAndClose(t *testing.T, s *rdpDVC, id byte, by rdpSide) {
	t.Helper()
	for _, step := range []struct {
		from rdpSide
		pdu  []byte
	}{
		{rdpServer, append([]byte{dvcCreate << 4, id}, dvcDisplayControl+"\x00"...)},
		{rdpClient, binary.LittleEndian.AppendUint32([]byte{dvcCreate << 4, id}, 0)},
		{by, []byte{dvcClose << 4, id}},
	} {
		if _, err := s.decide(step.from, step.pdu); err != nil {
			t.Fatal(err)
		}
	}
}

// Client-closed keeps the most recent rdpMaxDVCChannels ids; the oldest
// falls back to none, so late server data on it ends the connection again.
func TestRDPDVCClientClosedBound(t *testing.T) {
	s := &rdpDVC{}
	s.init()
	for id := range byte(rdpMaxDVCChannels + 1) {
		dvcOpenAndClose(t, s, id, rdpClient)
	}
	if len(s.closed) != rdpMaxDVCChannels || s.states[0] != dvcNone || s.states[rdpMaxDVCChannels] != dvcClientClosed {
		t.Fatalf("closed %v, states %v", s.closed, s.states)
	}
	if _, err := s.decide(rdpServer, []byte{dvcData << 4, 0, 'x'}); !errors.Is(err, errRDPViolation) {
		t.Fatalf("data on the evicted id: %v", err)
	}
	if frames, err := s.decide(rdpServer, []byte{dvcData << 4, rdpMaxDVCChannels, 'x'}); err != nil || frames != nil {
		t.Fatalf("data on a kept id: %v %v", frames, err)
	}
}

// A server-closing id still owes the client's answer, so it counts toward
// rdpMaxDVCChannels and is never evicted: past the bound a Create ends the
// connection.
func TestRDPDVCServerClosingCountsLive(t *testing.T) {
	s := &rdpDVC{}
	s.init()
	for id := range byte(rdpMaxDVCChannels) {
		dvcOpenAndClose(t, s, id, rdpServer)
	}
	create := append([]byte{dvcCreate << 4, rdpMaxDVCChannels}, dvcDisplayControl+"\x00"...)
	if _, err := s.decide(rdpServer, create); !errors.Is(err, errRDPViolation) {
		t.Fatalf("create past the bound: %v", err)
	}
	if frames, err := s.decide(rdpClient, []byte{dvcClose << 4, 0}); err != nil || len(frames) != 1 {
		t.Fatalf("the first id's answering Close: %v %v", frames, err)
	}
}
