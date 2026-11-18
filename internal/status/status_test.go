package status

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func TestBoardEncodesSortedRowsAndDecodesBack(t *testing.T) {
	b := NewBoard(42)
	next := t0.Add(time.Minute)
	b.Set(Device{Identity: "team/device/b", State: StateWaiting, Code: "BL011", Since: t0, NextRetry: &next})
	b.Set(Device{Identity: "team/device/a", State: StateRunning, Since: t0})
	doc, err := Decode(b.Latest())
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != Version || doc.PID != 42 || len(doc.Devices) != 2 {
		t.Fatalf("document = %+v", doc)
	}
	if doc.Devices[0].Identity != "team/device/a" || doc.Devices[1].Code != "BL011" || !doc.Devices[1].NextRetry.Equal(next) {
		t.Fatalf("rows = %+v, want a then b with its code and retry time", doc.Devices)
	}
	b.Remove("team/device/a")
	if doc, err = Decode(b.Latest()); err != nil || len(doc.Devices) != 1 {
		t.Fatalf("after Remove: %+v, %v", doc, err)
	}
}

// A row set again with the same state and code keeps its Since and, with the
// same retry time, publishes nothing new.
func TestBoardKeepsSinceForAnUnchangedState(t *testing.T) {
	b := NewBoard(1)
	b.Set(Device{Identity: "d", State: StateRunning, Since: t0})
	<-b.Changed()
	before := b.Latest()
	b.Set(Device{Identity: "d", State: StateRunning, Since: t0.Add(time.Hour)})
	select {
	case <-b.Changed():
		t.Fatal("an unchanged row signalled a change")
	default:
	}
	if !bytes.Equal(before, b.Latest()) {
		t.Fatal("an unchanged row re-encoded the document")
	}
	b.Set(Device{Identity: "d", State: StateParked, Code: "SE031", Since: t0.Add(time.Hour)})
	doc, err := Decode(b.Latest())
	if err != nil || !doc.Devices[0].Since.Equal(t0.Add(time.Hour)) {
		t.Fatalf("a changed state keeps the old Since: %+v, %v", doc, err)
	}
}

func TestDecodeRefusesInvalidDocuments(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown field":   `{"version":1,"pid":1,"devices":[],"login":"root"}`,
		"unknown version": `{"version":2,"pid":1,"devices":[]}`,
		"unknown state":   `{"version":1,"pid":1,"devices":[{"identity":"d","state":"exploded","since":"2026-11-17T12:00:00Z"}]}`,
		"row field":       `{"version":1,"pid":1,"devices":[{"identity":"d","state":"running","since":"2026-11-17T12:00:00Z","host":"x"}]}`,
		"trailing data":   `{"version":1,"pid":1,"devices":[]} {}`,
		"over the cap":    `{"version":1,"pid":1,"devices":[]}` + strings.Repeat(" ", MaxFrame),
	} {
		if _, err := Decode([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Decode = %v, want ErrInvalid", name, err)
		}
	}
}

// A full board of the longest rows fits one frame: config.MaxDevices devices
// (64; the status package does not import config), each with a 129-byte
// identity, the longest state, a code and both times.
func TestFullBoardFitsAFrame(t *testing.T) {
	const maxDevices, maxIdentity = 64, 64 + 1 + 64
	b := NewBoard(1 << 30)
	next := t0.Add(time.Hour)
	for i := range maxDevices {
		id := fmt.Sprintf("%03d%s", i, strings.Repeat("x", maxIdentity-3))
		b.Set(Device{Identity: id, State: StateDisconnected, Code: "SE040", Since: t0.Add(time.Nanosecond), NextRetry: &next})
	}
	if n := len(b.Latest()); n > MaxFrame {
		t.Fatalf("a full board encodes to %d bytes, over %d", n, MaxFrame)
	}
}

// A code not in the refusal code shape never reaches a row, and Decode refuses
// one.
func TestRowCodesHaveTheRefusalCodeShape(t *testing.T) {
	b := NewBoard(1)
	b.Set(Device{Identity: "a", State: StateWaiting, Code: strings.Repeat("A", 4096), Since: t0})
	doc, err := Decode(b.Latest())
	if err != nil || doc.Devices[0].Code != "" {
		t.Fatalf("row = %+v, %v; want the code dropped", doc, err)
	}
	for _, code := range []string{"se040", "SE04", "SE0400", "S1040", "SEA40"} {
		raw := fmt.Sprintf(`{"version":1,"pid":1,"devices":[{"identity":"a","state":"waiting","code":%q,"since":"2026-11-17T12:00:00Z"}]}`, code)
		if _, err := Decode([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode with code %q = %v, want ErrInvalid", code, err)
		}
	}
}
