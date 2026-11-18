// Package status holds the device service's status document: the state of
// each configured device, published by the service to the session launcher,
// which serves it read-only to `localport status`, `up` and `down`.
package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/localport/agent/internal/launcher"
)

// Version is the document version this agent writes and reads.
const Version = 1

// MaxFrame bounds one encoded document, on the wire and in the launcher.
const MaxFrame = launcher.MaxStatusFrame

// Device states.
const (
	StateRunning      = "running"
	StateConnecting   = "connecting"
	StatePaused       = "paused"
	StateDisconnected = "disconnected"
	StateWaiting      = "waiting"
	StateDraining     = "draining"
	StateParked       = "parked"
	StateRemoved      = "removed"
)

var validStates = []string{StateRunning, StateConnecting, StatePaused, StateDisconnected,
	StateWaiting, StateDraining, StateParked, StateRemoved}

// Device is one device's row. Code is the refusal behind waiting,
// disconnected, parked and removed; NextRetry is set while waiting or
// disconnected. It carries no address, login, key, serial or path.
type Device struct {
	Identity  string     `json:"identity"`
	State     string     `json:"state"`
	Code      string     `json:"code,omitempty"`
	Since     time.Time  `json:"since"`
	NextRetry *time.Time `json:"next_retry,omitempty"`
}

// Document is what the service publishes.
type Document struct {
	Version int      `json:"version"`
	PID     int      `json:"pid"`
	Devices []Device `json:"devices"`
}

// ErrInvalid refuses a document that is too large, not version Version,
// holds unknown fields or an unknown state.
var ErrInvalid = errors.New("invalid status document")

// Decode reads one document strictly.
func Decode(raw []byte) (*Document, error) {
	if len(raw) > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes, over %d", ErrInvalid, len(raw), MaxFrame)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if doc.Version != Version {
		return nil, fmt.Errorf("%w: version %d, this agent reads %d", ErrInvalid, doc.Version, Version)
	}
	for _, d := range doc.Devices {
		if !slices.Contains(validStates, d.State) {
			return nil, fmt.Errorf("%w: state %q", ErrInvalid, d.State)
		}
		if d.Code != "" && !validCode(d.Code) {
			return nil, fmt.Errorf("%w: code %q", ErrInvalid, d.Code)
		}
	}
	return &doc, nil
}

// validCode reports whether code has the shape of a refusal code, two
// uppercase letters and three digits (SE040). Codes arrive from the network,
// so a row carries nothing else in their place, which also bounds its size.
func validCode(code string) bool {
	if len(code) != 5 {
		return false
	}
	for i := range 5 {
		c := code[i]
		if i < 2 && (c < 'A' || c > 'Z') || i >= 2 && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// Board holds the latest state of each device and its encoded document. Set
// and Remove are safe for concurrent use and never wait on a reader: Latest
// loads the newest encoding without a lock, and Changed signals that a newer
// one exists.
type Board struct {
	pid     int
	latest  atomic.Pointer[[]byte]
	changed chan struct{}

	mu      sync.Mutex
	devices map[string]Device
}

// NewBoard returns an empty board for the process pid.
func NewBoard(pid int) *Board {
	b := &Board{pid: pid, devices: map[string]Device{}, changed: make(chan struct{}, 1)}
	b.encodeLocked()
	return b
}

// Set replaces the row of d.Identity. A row whose state and code are unchanged
// keeps its Since. A code not in the refusal code shape is dropped.
func (b *Board) Set(d Device) {
	if !validCode(d.Code) {
		d.Code = ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if prev, ok := b.devices[d.Identity]; ok && prev.State == d.State && prev.Code == d.Code {
		d.Since = prev.Since
		if equalTimes(prev.NextRetry, d.NextRetry) {
			return
		}
	}
	b.devices[d.Identity] = d
	b.encodeLocked()
}

// Remove drops the row of identity.
func (b *Board) Remove(identity string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.devices[identity]; !ok {
		return
	}
	delete(b.devices, identity)
	b.encodeLocked()
}

// Latest returns the newest encoded document. The slice is never modified.
func (b *Board) Latest() []byte { return *b.latest.Load() }

// Changed receives a value after each change; one pending value covers any
// number of changes.
func (b *Board) Changed() <-chan struct{} { return b.changed }

func (b *Board) encodeLocked() {
	doc := Document{Version: Version, PID: b.pid, Devices: make([]Device, 0, len(b.devices))}
	for _, d := range b.devices {
		doc.Devices = append(doc.Devices, d)
	}
	slices.SortFunc(doc.Devices, func(x, y Device) int { return strings.Compare(x.Identity, y.Identity) })
	raw, err := json.Marshal(doc)
	if err != nil {
		// Only times and strings: an encoding failure is a programming error.
		panic(fmt.Sprintf("status: encode: %v", err))
	}
	b.latest.Store(&raw)
	select {
	case b.changed <- struct{}{}:
	default:
	}
}

func equalTimes(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}
