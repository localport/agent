package recording

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/localport/agent/internal/errcode"
	"github.com/localport/agent/internal/security"
)

const (
	// SpoolCap bounds the bytes every spool entry counts together: its segment
	// files and its meta budget (see spoolEntry). Entry creation, a segment
	// write or a hash reservation that would pass it is refused.
	SpoolCap = 32 << 20
	// MinFreeSpace is the free space the spool's filesystem must keep: a
	// segment write is refused while less is available.
	MinFreeSpace = 64 << 20

	// PolicyBestEffort and PolicyStrict are the recording policies a session certificate's
	// rec carries.
	PolicyBestEffort = "best_effort"
	PolicyStrict     = "strict"

	// hashAllowance is the meta.json room one segment hash takes: 44 base64
	// characters, two quotes and a comma, rounded up.
	hashAllowance = 48

	metaName    = "meta.json"
	segSuffix   = ".seg"
	maxMetaSize = 4 << 20
)

var (
	// ErrSpoolFull refuses an entry, a segment write or a hash reservation
	// that would pass SpoolCap; a recording whose segment is refused completes
	// with ReasonSpoolFull.
	ErrSpoolFull = errcode.New(errcode.SpoolFull)
	// ErrDiskLow refuses a segment write while the spool's filesystem has
	// less than MinFreeSpace available, and wraps a segment write that found
	// the filesystem or quota full; the recording completes with
	// ReasonDiskLow.
	ErrDiskLow = errcode.New(errcode.DiskLow)
	// ErrNoEntry is returned for an id the spool holds no entry for.
	ErrNoEntry = errors.New("recording: no spool entry")
	// ErrEntryExists is returned by CreateEntry for an id already present.
	ErrEntryExists = errors.New("recording: spool entry exists")
	// ErrMeta is returned for metadata that fails validation, on write or on
	// the start-up scan.
	ErrMeta = errors.New("recording: invalid spool metadata")
	// ErrStrayFile marks a file the start-up scan removed from an entry: a
	// temporary file left by a crash, or a name the spool never writes.
	ErrStrayFile = errors.New("recording: stray file in spool entry")
)

// Meta is an entry's meta.json: the unsigned fields the uploader needs to
// sign and send the open and the complete after a restart. Signatures are
// never stored; they are made with the certificate of the carrying session
// mux when each request is sent.
type Meta struct {
	ID string `json:"id"`
	// SessionID is the session id of the connection the recording belongs to
	// (the edge's notice); a connection has one recording per session channel, plus one for its port forwards.
	SessionID string `json:"session_id"`
	// Identifier is the local device identity the session certificate was for. The
	// uploader keys the device's session mux on it.
	Identifier string `json:"identifier"`
	// LastAcceptedAt is the session start, then the time of each segment the
	// server accepted; see LocalDeadline.
	LastAcceptedAt time.Time `json:"last_accepted_at"`
	WrappedDEK     []byte    `json:"wrapped_dek"`
	KeySHA256      []byte    `json:"key_sha256"`
	Policy         string    `json:"policy"`
	// Certificate is the SSH user certificate that admitted the session's
	// connection (wire form). The open sends it; the open that finds no row
	// creates it from the certificate, so a resumed open after a restart
	// still has it.
	Certificate []byte `json:"certificate,omitempty"`
	// Sealed is the count of segments sealed.
	Sealed uint32 `json:"sealed"`
	// Acked is the highest count of segments the server acknowledged, and
	// AckedChain the chain value over those segments (empty while Acked is 0).
	Acked      uint32 `json:"acked"`
	AckedChain []byte `json:"acked_chain,omitempty"`
	// Hashes holds the hash of each segment from index Acked to Sealed-1.
	Hashes [][]byte `json:"hashes,omitempty"`
	// Complete holds the unsigned complete fields once they are known.
	Complete *Completion `json:"complete,omitempty"`
	// FinalIndex is the index of the final segment, written before that
	// segment can be sent.
	FinalIndex *uint32 `json:"final_index,omitempty"`
	// Channels is the cumulative channel count the open of a live start
	// carries (Client.Open). It is never stored: a resumed open carries none.
	Channels int32 `json:"-"`
	// ObjectVersion is the segment object version of the entry's segments,
	// written as ObjectVersion by every meta write. An entry read with
	// another (absent before version 2) is dropped by the start-up scan.
	ObjectVersion int `json:"object_version"`
}

// Chain returns the chain value over all Sealed segments.
func (m *Meta) Chain() []byte {
	chain := m.AckedChain
	if len(chain) == 0 {
		chain = nil
	}
	for _, h := range m.Hashes {
		chain = ChainStep(chain, [32]byte(h))
	}
	return chain
}

func (m *Meta) validate() error {
	switch {
	case m.ObjectVersion != ObjectVersion:
		return fmt.Errorf("%w: segment object version %d, want %d", ErrMeta, m.ObjectVersion, ObjectVersion)
	case !validID(m.ID):
		return fmt.Errorf("%w: id %q is not a canonical UUID", ErrMeta, m.ID)
	case !validID(m.SessionID):
		return fmt.Errorf("%w: session id %q is not a canonical UUID", ErrMeta, m.SessionID)
	case m.Identifier == "":
		return fmt.Errorf("%w: device identity missing", ErrMeta)
	case m.LastAcceptedAt.IsZero():
		return fmt.Errorf("%w: last_accepted_at missing", ErrMeta)
	case len(m.WrappedDEK) == 0:
		return fmt.Errorf("%w: wrapped_dek missing", ErrMeta)
	case len(m.KeySHA256) != 32:
		return fmt.Errorf("%w: key_sha256 is not 32 bytes", ErrMeta)
	case m.Policy != PolicyBestEffort && m.Policy != PolicyStrict:
		return fmt.Errorf("%w: policy %q", ErrMeta, m.Policy)
	case len(m.Certificate) > MaxCertificate:
		return fmt.Errorf("%w: certificate of %d bytes", ErrMeta, len(m.Certificate))
	case m.Acked > m.Sealed:
		return fmt.Errorf("%w: counts acked %d, sealed %d out of order", ErrMeta, m.Acked, m.Sealed)
	case (m.Acked == 0) != (len(m.AckedChain) == 0) || (m.Acked != 0 && len(m.AckedChain) != 32):
		return fmt.Errorf("%w: acked_chain does not match acked %d", ErrMeta, m.Acked)
	case uint64(len(m.Hashes)) != uint64(m.Sealed-m.Acked):
		return fmt.Errorf("%w: %d hashes for %d unacknowledged segments", ErrMeta, len(m.Hashes), m.Sealed-m.Acked)
	}
	for _, h := range m.Hashes {
		if len(h) != 32 {
			return fmt.Errorf("%w: segment hash is not 32 bytes", ErrMeta)
		}
	}
	return nil
}

// Entry is one recording found by the start-up scan: its metadata and the
// indices of the segment files present, ascending.
type Entry struct {
	Meta    Meta
	Indices []uint32
}

// Dropped is a removal the start-up scan made. Path is empty when the whole
// entry was removed and names the file otherwise. Err says why, and also
// carries a failed removal, which the next scan retries.
type Dropped struct {
	ID   string
	Path string
	Err  error
}

// Scan is the result of the start-up scan.
type Scan struct {
	Entries []Entry
	Dropped []Dropped
}

// Spool is the on-disk store of recording entries, <dir>/<id>/meta.json and
// <dir>/<id>/<index>.seg, directories 0700 and files 0600, each file written
// atomically. One Spool serves an agent process and is safe for concurrent
// use. Writes to one entry are serialized by that entry's lock; the spool's
// own lock guards only the entry set and the byte count and is never held
// across I/O. Lock order: entry, then spool.
type Spool struct {
	dir string
	// freeBytes reports the bytes available on the filesystem holding a path.
	freeBytes func(path string) (uint64, error)
	// writeFile writes a private file atomically; tests replace it.
	writeFile func(path string, data []byte) error

	mu      sync.Mutex
	used    int64
	entries map[string]*spoolEntry
}

// spoolEntry is one entry's accounting. metaBudget is what the entry's
// meta.json counts: what metaBudget returns for its last written meta, plus
// hashAllowance for each hash reserved since. Every meta write the uploader
// makes after it reserved the hashes it adds therefore fits in the budget and
// never needs room under SpoolCap.
type spoolEntry struct {
	mu         sync.Mutex
	gone       bool
	metaBudget int64
	segs       map[uint32]int64
}

func (e *spoolEntry) size() int64 {
	n := e.metaBudget
	for _, s := range e.segs {
		n += s
	}
	return n
}

// OpenSpool creates dir under root as a private directory (security.
// EnsurePrivateDir, root followed only with followRoot), then scans it. A
// directory whose name is not a canonical UUID, or that is a symlink, is
// ignored and left in place. In an entry, temporary files and names the
// spool never writes are removed; an entry whose meta.json is missing,
// unreadable, not private or invalid is removed whole. The byte count starts
// from what the scan kept.
func OpenSpool(root, dir string, followRoot bool) (*Spool, Scan, error) {
	if err := security.EnsurePrivateDir(root, dir, followRoot); err != nil {
		return nil, Scan{}, fmt.Errorf("recording spool %s: %w", dir, err)
	}
	s := &Spool{dir: dir, freeBytes: availableBytes, writeFile: security.WritePrivateFileAtomic, entries: make(map[string]*spoolEntry)}
	scan, err := s.scan()
	if err != nil {
		return nil, Scan{}, err
	}
	return s, scan, nil
}

func (s *Spool) scan() (Scan, error) {
	des, err := os.ReadDir(s.dir)
	if err != nil {
		return Scan{}, fmt.Errorf("recording spool %s: %w", s.dir, err)
	}
	var scan Scan
	for _, de := range des {
		id := de.Name()
		if !de.IsDir() || !validID(id) {
			continue
		}
		entry, e, dropped := s.scanEntry(id)
		scan.Dropped = append(scan.Dropped, dropped...)
		if e == nil {
			continue
		}
		s.entries[id] = e
		s.used += e.size()
		scan.Entries = append(scan.Entries, entry)
	}
	return scan, nil
}

// scanEntry reads one entry; a nil *spoolEntry means it was removed.
func (s *Spool) scanEntry(id string) (Entry, *spoolEntry, []Dropped) {
	path := filepath.Join(s.dir, id)
	dropEntry := func(dropped []Dropped, cause error) (Entry, *spoolEntry, []Dropped) {
		if err := os.RemoveAll(path); err != nil {
			cause = errors.Join(cause, err)
		}
		return Entry{}, nil, append(dropped, Dropped{ID: id, Err: cause})
	}
	des, err := os.ReadDir(path)
	if err != nil {
		return dropEntry(nil, err)
	}
	var dropped []Dropped
	e := &spoolEntry{segs: make(map[uint32]int64)}
	for _, de := range des {
		name := de.Name()
		if name == metaName && de.Type().IsRegular() {
			continue
		}
		index, ok := parseSegName(name)
		if ok && de.Type().IsRegular() {
			info, err := de.Info()
			if err == nil {
				e.segs[index] = info.Size()
				continue
			}
		}
		file := filepath.Join(path, name)
		cause := fmt.Errorf("%w: %s", ErrStrayFile, name)
		if err := os.RemoveAll(file); err != nil {
			cause = errors.Join(cause, err)
		}
		dropped = append(dropped, Dropped{ID: id, Path: file, Err: cause})
	}
	meta, err := readMeta(path, id)
	if err != nil {
		return dropEntry(dropped, err)
	}
	if e.metaBudget, err = metaBudget(meta); err != nil {
		return dropEntry(dropped, err)
	}
	indices := make([]uint32, 0, len(e.segs))
	for i := range e.segs {
		indices = append(indices, i)
	}
	slices.Sort(indices)
	return Entry{Meta: meta, Indices: indices}, e, dropped
}

func readMeta(dir, id string) (Meta, error) {
	data, err := readPrivate(filepath.Join(dir, metaName), maxMetaSize)
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("%w: %w", ErrMeta, err)
	}
	if err := m.validate(); err != nil {
		return Meta{}, err
	}
	if m.ID != id {
		return Meta{}, fmt.Errorf("%w: id %s in entry %s", ErrMeta, m.ID, id)
	}
	return m, nil
}

// metaBudget returns the largest meta.json m can become without a new
// segment hash: complete fields with the longest reason, an acknowledged
// chain, the widest counters and the longest timestamps, and one hash more
// than m holds, which also counts the hashes key an empty list omits.
func metaBudget(m Meta) (int64, error) {
	widest := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(23*3600+59*60)))
	reason := ""
	for _, r := range []string{ReasonSpoolFull, ReasonDiskLow, ReasonAgentRestart, ReasonRecordingFailed} {
		if len(r) > len(reason) {
			reason = r
		}
	}
	m.Hashes = append(slices.Clone(m.Hashes), make([]byte, sha256.Size))
	m.Sealed, m.Acked = math.MaxUint32, math.MaxUint32
	widestIndex := uint32(math.MaxUint32)
	m.FinalIndex = &widestIndex
	m.AckedChain = make([]byte, sha256.Size)
	m.LastAcceptedAt = widest
	m.Complete = &Completion{
		Segments: math.MaxUint32, FinalHash: make([]byte, sha256.Size), EndedAt: widest,
		Incomplete: true, Final: true, Reason: reason,
	}
	data, err := json.Marshal(m)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrMeta, err)
	}
	return int64(len(data)), nil
}

func readPrivate(path string, limit int64) ([]byte, error) {
	f, err := security.OpenPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("read %s: larger than %d bytes", path, limit)
	}
	return data, nil
}

// Used returns the bytes the spool's entries count against SpoolCap.
func (s *Spool) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// CreateEntry creates the entry for m.ID and writes its meta.json (fsync
// before return). The entry's meta budget is reserved against SpoolCap, so
// a full spool refuses it with ErrSpoolFull; the free-space guard applies to
// segment writes only.
func (s *Spool) CreateEntry(m Meta) error {
	data, err := marshalMeta(m)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, m.ID)
	e := &spoolEntry{segs: make(map[uint32]int64)}
	e.mu.Lock()
	defer e.mu.Unlock()
	s.mu.Lock()
	if _, ok := s.entries[m.ID]; ok {
		s.mu.Unlock()
		return ErrEntryExists
	}
	s.entries[m.ID] = e
	s.mu.Unlock()

	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		s.forget(m.ID, e)
		if err == nil {
			return ErrEntryExists
		}
		return fmt.Errorf("recording spool entry %s: %w", m.ID, err)
	}
	if err := security.EnsurePrivateDir(s.dir, path, false); err != nil {
		s.forget(m.ID, e)
		return fmt.Errorf("recording spool entry %s: %w", m.ID, err)
	}
	// Best effort (a no-op on Windows): the entry survives a power loss once
	// meta.json is written; a directory without it is dropped on the next scan.
	security.SyncDir(s.dir)
	if err := s.writeMeta(e, path, m, data); err != nil {
		_ = os.RemoveAll(path)
		s.forget(m.ID, e)
		return err
	}
	return nil
}

// WriteMeta rewrites the meta.json of an existing entry atomically: a crash
// leaves the old file or the new one. A meta whose new hashes were each
// reserved (ReserveHash) fits the entry's budget; any other growth is
// reserved against SpoolCap and may be refused with ErrSpoolFull.
func (s *Spool) WriteMeta(m Meta) error {
	data, err := marshalMeta(m)
	if err != nil {
		return err
	}
	e, err := s.lock(m.ID)
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	return s.writeMeta(e, filepath.Join(s.dir, m.ID), m, data)
}

func marshalMeta(m Meta) ([]byte, error) {
	m.ObjectVersion = ObjectVersion
	if err := m.validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMeta, err)
	}
	return data, nil
}

// writeMeta writes data, the encoding of m, and moves the entry's meta budget
// to m's: growth is reserved before the write, the release of spent hash
// reservations and acknowledged hashes follows it. It runs with e.mu held.
func (s *Spool) writeMeta(e *spoolEntry, dir string, m Meta, data []byte) error {
	budget, err := metaBudget(m)
	if err != nil {
		return err
	}
	delta := budget - e.metaBudget
	if delta > 0 {
		if err := s.reserve(delta); err != nil {
			return err
		}
	}
	if err := s.writeFile(filepath.Join(dir, metaName), data); err != nil {
		if delta > 0 {
			s.adjust(-delta)
		}
		return fmt.Errorf("recording spool: %w", err)
	}
	if delta < 0 {
		s.adjust(delta)
	}
	e.metaBudget = budget
	return nil
}

// ReserveHash reserves the meta.json room of one more segment hash of entry
// id, refusing with ErrSpoolFull past SpoolCap. The uploader reserves before
// it takes a segment and releases (ReleaseHash) when it does not take it; the
// next meta write spends the reservation.
func (s *Spool) ReserveHash(id string) error {
	e, err := s.lock(id)
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	if err := s.reserve(hashAllowance); err != nil {
		return err
	}
	e.metaBudget += hashAllowance
	return nil
}

// ReleaseHash returns a ReserveHash reservation that no segment took.
func (s *Spool) ReleaseHash(id string) {
	e, err := s.lock(id)
	if err != nil {
		return
	}
	defer e.mu.Unlock()
	e.metaBudget -= hashAllowance
	s.adjust(-hashAllowance)
}

// WriteSegment writes seg's object as <id>/<index>.seg. It refuses with
// ErrDiskLow while the filesystem has less than MinFreeSpace available and
// with ErrSpoolFull when the write would pass SpoolCap; nothing is written
// then. Rewriting an index replaces the file and counts the size difference.
func (s *Spool) WriteSegment(id string, seg Segment) error {
	e, err := s.lock(id)
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	free, err := s.freeBytes(s.dir)
	if err != nil {
		return fmt.Errorf("recording spool free space: %w", err)
	}
	if free < MinFreeSpace {
		return ErrDiskLow
	}
	size := int64(len(seg.Object))
	delta := size - e.segs[seg.Index]
	if err := s.reserve(delta); err != nil {
		return err
	}
	if err := s.writeFile(s.segPath(id, seg.Index), seg.Object); err != nil {
		s.adjust(-delta)
		if diskFull(err) {
			return fmt.Errorf("%w: %w", ErrDiskLow, err)
		}
		return fmt.Errorf("recording spool: %w", err)
	}
	e.segs[seg.Index] = size
	return nil
}

// ReadSegment returns the object of a spooled segment. An index without a
// file returns an error wrapping fs.ErrNotExist.
func (s *Spool) ReadSegment(id string, index uint32) ([]byte, error) {
	e, err := s.lock(id)
	if err != nil {
		return nil, err
	}
	defer e.mu.Unlock()
	if _, ok := e.segs[index]; !ok {
		return nil, fmt.Errorf("recording spool %s segment %d: %w", id, index, fs.ErrNotExist)
	}
	return readPrivate(s.segPath(id, index), MaxObject)
}

// RemoveSegment deletes a segment file, once the server acknowledged it. A
// missing file is not an error.
func (s *Spool) RemoveSegment(id string, index uint32) error {
	e, err := s.lock(id)
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	size, ok := e.segs[index]
	if !ok {
		return nil
	}
	if err := os.Remove(s.segPath(id, index)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("recording spool: %w", err)
	}
	delete(e.segs, index)
	s.adjust(-size)
	return nil
}

// Remove deletes an entry's directory. An unknown id is not an error. When
// the removal fails the entry stays, counted, for a retry.
func (s *Spool) Remove(id string) error {
	s.mu.Lock()
	e := s.entries[id]
	s.mu.Unlock()
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gone {
		return nil
	}
	if err := os.RemoveAll(filepath.Join(s.dir, id)); err != nil {
		return fmt.Errorf("recording spool: %w", err)
	}
	s.forget(id, e)
	return nil
}

// lock returns the live entry for id with its lock held.
func (s *Spool) lock(id string) (*spoolEntry, error) {
	s.mu.Lock()
	e := s.entries[id]
	s.mu.Unlock()
	if e == nil {
		return nil, ErrNoEntry
	}
	e.mu.Lock()
	if e.gone {
		e.mu.Unlock()
		return nil, ErrNoEntry
	}
	return e, nil
}

// forget drops e from the set and the count; it runs with e.mu held.
func (s *Spool) forget(id string, e *spoolEntry) {
	e.gone = true
	size := e.size()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[id] == e {
		delete(s.entries, id)
	}
	s.used -= size
}

// reserve adds delta to the count, refusing growth past SpoolCap.
func (s *Spool) reserve(delta int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if delta > 0 && s.used+delta > SpoolCap {
		return ErrSpoolFull
	}
	s.used += delta
	return nil
}

func (s *Spool) adjust(delta int64) {
	s.mu.Lock()
	s.used += delta
	s.mu.Unlock()
}

func (s *Spool) segPath(id string, index uint32) string {
	return filepath.Join(s.dir, id, strconv.FormatUint(uint64(index), 10)+segSuffix)
}

// parseSegName accepts only the names segPath writes: decimal, no sign or
// leading zero.
func parseSegName(name string) (uint32, bool) {
	digits, ok := strings.CutSuffix(name, segSuffix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != digits {
		return 0, false
	}
	return uint32(n), true
}

// validID reports whether id is a canonical lowercase UUID in text form, the
// only shape used as a spool path component.
func validID(id string) bool {
	if len(id) != IDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
