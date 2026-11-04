package recording

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

const (
	spoolID1 = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	spoolID2 = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c"
)

func plentyFree(string) (uint64, error) { return 1 << 40, nil }

func openTestSpool(t *testing.T, dir string) (*Spool, Scan) {
	t.Helper()
	s, scan, err := OpenSpool(filepath.Dir(dir), dir, true)
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	s.freeBytes = plentyFree
	return s, scan
}

func spoolDir(t *testing.T) string {
	return filepath.Join(t.TempDir(), "recordings")
}

func testMeta(id string) Meta {
	return Meta{
		ID:             id,
		SessionID:      testSessionID,
		Identifier:     "device-1",
		LastAcceptedAt: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC),
		WrappedDEK:     bytes.Repeat([]byte{1}, 100),
		KeySHA256:      bytes.Repeat([]byte{0xaa}, 32),
		Policy:         PolicyBestEffort,
	}
}

// sealedMeta advances m by one sealed, unacknowledged segment.
func sealedMeta(m Meta, h byte) Meta {
	m.Sealed++
	m.Hashes = append(m.Hashes, bytes.Repeat([]byte{h}, 32))
	return m
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestSpoolLayoutAndModes(t *testing.T) {
	dir := spoolDir(t)
	s, scan := openTestSpool(t, dir)
	if len(scan.Entries) != 0 || len(scan.Dropped) != 0 {
		t.Fatalf("empty spool scan = %+v", scan)
	}
	m := testMeta(spoolID1)
	if err := s.CreateEntry(m); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEntry(m); !errors.Is(err, ErrEntryExists) {
		t.Fatalf("second CreateEntry = %v, want ErrEntryExists", err)
	}
	m = sealedMeta(sealedMeta(m, 1), 2)
	for i := uint32(0); i < 2; i++ {
		if err := s.WriteSegment(spoolID1, Segment{Index: i, Object: []byte(fmt.Sprintf("object-%d", i))}); err != nil {
			t.Fatal(err)
		}
	}
	m.Complete = &Completion{Segments: 2, FinalHash: m.Hashes[1], EndedAt: time.Unix(1767225600, 0).UTC(), Final: true}
	if err := s.WriteMeta(m); err != nil {
		t.Fatal(err)
	}

	entry := filepath.Join(dir, spoolID1)
	for path, want := range map[string]os.FileMode{
		dir:                               0o700,
		entry:                             0o700,
		filepath.Join(entry, "meta.json"): 0o600,
		filepath.Join(entry, "0.seg"):     0o600,
		filepath.Join(entry, "1.seg"):     0o600,
	} {
		if got := mode(t, path); got != want {
			t.Errorf("mode %s = %o, want %o", path, got, want)
		}
	}
	names, err := os.ReadDir(entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 {
		t.Errorf("entry holds %d files, want meta.json and two segments", len(names))
	}

	used := s.Used()
	s2, scan := openTestSpool(t, dir)
	if len(scan.Dropped) != 0 || len(scan.Entries) != 1 {
		t.Fatalf("rescan = %+v", scan)
	}
	got := scan.Entries[0]
	if !reflect.DeepEqual(got.Meta, m) {
		t.Errorf("rescanned meta = %+v, want %+v", got.Meta, m)
	}
	if !reflect.DeepEqual(got.Indices, []uint32{0, 1}) {
		t.Errorf("indices = %v", got.Indices)
	}
	if s2.Used() != used {
		t.Errorf("rescanned count = %d, want %d", s2.Used(), used)
	}
	obj, err := s2.ReadSegment(spoolID1, 1)
	if err != nil || string(obj) != "object-1" {
		t.Errorf("ReadSegment = %q, %v", obj, err)
	}
	if !bytes.Equal(got.Meta.Chain(), ChainStep(ChainStep(nil, [32]byte(m.Hashes[0])), [32]byte(m.Hashes[1]))) {
		t.Error("Chain does not fold the hashes")
	}
}

func TestSpoolMetaRewriteSurvivesCrash(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	m := testMeta(spoolID1)
	if err := s.CreateEntry(m); err != nil {
		t.Fatal(err)
	}
	m = sealedMeta(m, 7)
	if err := s.WriteMeta(m); err != nil {
		t.Fatal(err)
	}
	// A crash after the temporary write and before the rename leaves the
	// temporary files beside the installed ones.
	entry := filepath.Join(dir, spoolID1)
	for _, name := range []string{"meta.json.tmp", "0.seg.tmp", "00.seg"} {
		if err := os.WriteFile(filepath.Join(entry, name), []byte("{partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	s2, scan := openTestSpool(t, dir)
	if len(scan.Entries) != 1 || !reflect.DeepEqual(scan.Entries[0].Meta, m) {
		t.Fatalf("rescan entries = %+v, want the last installed meta", scan.Entries)
	}
	if len(scan.Dropped) != 3 {
		t.Fatalf("dropped = %+v, want the three stray files", scan.Dropped)
	}
	for _, d := range scan.Dropped {
		if !errors.Is(d.Err, ErrStrayFile) || d.Path == "" {
			t.Errorf("dropped %+v, want a stray file", d)
		}
		if _, err := os.Lstat(d.Path); !os.IsNotExist(err) {
			t.Errorf("%s left on disk", d.Path)
		}
	}
	if err := s2.WriteMeta(m); err != nil {
		t.Fatalf("rewrite after rescan: %v", err)
	}
}

func TestSpoolCap(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Fatal(err)
	}
	object := make([]byte, 4<<20)
	const fit = SpoolCap/(4<<20) - 1 // meta.json takes part of the last slot
	written := uint32(0)
	for ; ; written++ {
		err := s.WriteSegment(spoolID1, Segment{Index: written, Object: object})
		if errors.Is(err, ErrSpoolFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if written > fit {
			t.Fatalf("wrote %d segments of %d bytes past the %d-byte cap", written+1, len(object), SpoolCap)
		}
	}
	if written != fit {
		t.Fatalf("refused after %d segments, want %d", written, fit)
	}
	if _, err := os.Lstat(filepath.Join(dir, spoolID1, fmt.Sprintf("%d.seg", written))); !os.IsNotExist(err) {
		t.Fatal("refused segment was written")
	}
	used := s.Used()

	// The count is rebuilt from disk: a reopened spool refuses the same write.
	s2, _ := openTestSpool(t, dir)
	if s2.Used() != used {
		t.Fatalf("reopened count = %d, want %d", s2.Used(), used)
	}
	if err := s2.WriteSegment(spoolID1, Segment{Index: written, Object: object}); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("write after reopen = %v, want ErrSpoolFull", err)
	}
	if err := s2.RemoveSegment(spoolID1, 0); err != nil {
		t.Fatal(err)
	}
	if err := s2.WriteSegment(spoolID1, Segment{Index: written, Object: object}); err != nil {
		t.Fatalf("write after freeing a segment: %v", err)
	}
}

func TestSpoolDiskLow(t *testing.T) {
	s, _ := openTestSpool(t, spoolDir(t))
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Fatal(err)
	}
	free := uint64(MinFreeSpace - 1)
	s.freeBytes = func(string) (uint64, error) { return free, nil }
	used := s.Used()
	if err := s.WriteSegment(spoolID1, Segment{Index: 0, Object: []byte("x")}); !errors.Is(err, ErrDiskLow) {
		t.Fatalf("WriteSegment with %d free = %v, want ErrDiskLow", free, err)
	}
	if s.Used() != used {
		t.Error("refused write changed the count")
	}
	if _, err := os.Lstat(filepath.Join(s.dir, spoolID1, "0.seg")); !os.IsNotExist(err) {
		t.Fatal("refused segment was written")
	}
	statErr := errors.New("statfs failed")
	s.freeBytes = func(string) (uint64, error) { return 0, statErr }
	if err := s.WriteSegment(spoolID1, Segment{Index: 0, Object: []byte("x")}); !errors.Is(err, statErr) {
		t.Fatalf("WriteSegment with a failed statfs = %v", err)
	}
	free = MinFreeSpace
	s.freeBytes = func(string) (uint64, error) { return free, nil }
	if err := s.WriteSegment(spoolID1, Segment{Index: 0, Object: []byte("x")}); err != nil {
		t.Fatalf("WriteSegment with %d free = %v", free, err)
	}
}

// Every entry counts the largest meta.json it can reach plus its reserved
// hashes, so on a spool filled to SpoolCap each entry can still write its
// hashes, its complete fields and its acknowledgements, while a new entry, a
// new hash and growth that nothing reserved are refused.
func TestSpoolMetaWritesFitTheirBudget(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	const entries, hashes = 40, 3
	ids := make([]string, entries)
	for i := range ids {
		ids[i] = fmt.Sprintf("0190a1b2-c3d4-7e5f-8a9b-%012x", i)
		if err := s.CreateEntry(testMeta(ids[i])); err != nil {
			t.Fatal(err)
		}
		for range hashes {
			if err := s.ReserveHash(ids[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.WriteSegment(ids[0], Segment{Index: 0, Object: make([]byte, SpoolCap-s.Used())}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateEntry(testMeta(spoolID2)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("CreateEntry on a full spool = %v, want ErrSpoolFull", err)
	}
	if err := s.ReserveHash(ids[1]); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("ReserveHash on a full spool = %v, want ErrSpoolFull", err)
	}
	for _, id := range ids {
		m := testMeta(id)
		for h := range hashes {
			m = sealedMeta(m, byte(h))
		}
		if err := s.WriteMeta(m); err != nil {
			t.Fatalf("WriteMeta with reserved hashes on a full spool: %v", err)
		}
		m.Complete = &Completion{Segments: hashes, FinalHash: m.Chain(), EndedAt: time.Now(), Incomplete: true, Reason: ReasonRecordingFailed}
		if err := s.WriteMeta(m); err != nil {
			t.Fatalf("WriteMeta with complete fields on a full spool: %v", err)
		}
		m.AckedChain, m.Acked, m.Hashes = m.Chain(), hashes, nil
		if err := s.WriteMeta(m); err != nil {
			t.Fatalf("WriteMeta of the acknowledgement on a full spool: %v", err)
		}
		if s.Used() > SpoolCap {
			t.Fatalf("count %d past the %d cap", s.Used(), SpoolCap)
		}
	}

	before, err := os.ReadFile(filepath.Join(dir, ids[0], metaName))
	if err != nil {
		t.Fatal(err)
	}
	used := s.Used()
	grown := testMeta(ids[0])
	for i := range 2 * SpoolCap / hashAllowance / 1000 {
		grown = sealedMeta(grown, byte(i))
	}
	if err := s.WriteMeta(grown); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("WriteMeta of unreserved growth on a full spool = %v, want ErrSpoolFull", err)
	}
	if s.Used() != used {
		t.Fatalf("count %d after the refusal, want %d", s.Used(), used)
	}
	if after, err := os.ReadFile(filepath.Join(dir, ids[0], metaName)); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("meta.json changed by a refused write: %v", err)
	}
}

func TestAvailableBytes(t *testing.T) {
	n, err := availableBytes(t.TempDir())
	if err != nil || n == 0 {
		t.Fatalf("availableBytes = %d, %v", n, err)
	}
}

func TestSpoolScanDropsCorruptEntries(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteSegment(spoolID1, Segment{Index: 0, Object: []byte("seg")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spoolID1, "meta.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An entry with no meta.json at all.
	if err := os.Mkdir(filepath.Join(dir, spoolID2), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spoolID2, "0.seg"), []byte("seg"), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, scan := openTestSpool(t, dir)
	if len(scan.Entries) != 0 {
		t.Fatalf("entries = %+v, want none", scan.Entries)
	}
	if len(scan.Dropped) != 2 {
		t.Fatalf("dropped = %+v, want both entries", scan.Dropped)
	}
	if !errors.Is(scan.Dropped[0].Err, ErrMeta) || scan.Dropped[0].ID != spoolID1 || scan.Dropped[0].Path != "" {
		t.Errorf("dropped[0] = %+v, want the corrupt meta entry", scan.Dropped[0])
	}
	for _, id := range []string{spoolID1, spoolID2} {
		if _, err := os.Lstat(filepath.Join(dir, id)); !os.IsNotExist(err) {
			t.Errorf("entry %s left on disk", id)
		}
	}
	if s2.Used() != 0 {
		t.Errorf("count = %d after dropping every entry", s2.Used())
	}
	if _, scan := openTestSpool(t, dir); len(scan.Dropped)+len(scan.Entries) != 0 {
		t.Errorf("third scan = %+v, want nothing left", scan)
	}
}

func TestSpoolScanIgnoresNonUUIDNames(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Fatal(err)
	}
	// A valid entry reached through a symlink or a non-canonical name is not
	// an entry: it is neither read, counted nor removed.
	other := t.TempDir()
	if err := os.Rename(filepath.Join(dir, spoolID1), filepath.Join(other, spoolID1)); err != nil {
		t.Fatal(err)
	}
	crafted := []string{"0190A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B", "not-a-uuid", "..x", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5"}
	for _, name := range crafted {
		if err := os.Symlink(filepath.Join(other, spoolID1), filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(other, spoolID1), filepath.Join(dir, spoolID2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5g"), 0o700); err != nil {
		t.Fatal(err)
	}

	s2, scan := openTestSpool(t, dir)
	if len(scan.Entries)+len(scan.Dropped) != 0 || s2.Used() != 0 {
		t.Fatalf("scan = %+v, count %d; want crafted names ignored", scan, s2.Used())
	}
	for _, name := range append(crafted, spoolID2, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5g") {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s removed: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(other, spoolID1, "meta.json")); err != nil {
		t.Errorf("symlink target touched: %v", err)
	}
	bad := testMeta("../" + spoolID1[3:])
	if err := s2.CreateEntry(bad); !errors.Is(err, ErrMeta) {
		t.Errorf("CreateEntry with a traversal id = %v, want ErrMeta", err)
	}
}

func TestSpoolRemoveAndCount(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	for _, id := range []string{spoolID1, spoolID2} {
		if err := s.CreateEntry(testMeta(id)); err != nil {
			t.Fatal(err)
		}
	}
	afterCreate := s.Used()
	for i := uint32(0); i < 3; i++ {
		if err := s.WriteSegment(spoolID1, Segment{Index: i, Object: make([]byte, 100)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.WriteSegment(spoolID2, Segment{Index: 0, Object: make([]byte, 50)}); err != nil {
		t.Fatal(err)
	}
	if got := s.Used(); got != afterCreate+350 {
		t.Fatalf("count = %d, want %d", got, afterCreate+350)
	}
	// A rewrite of one index counts the size difference.
	if err := s.WriteSegment(spoolID1, Segment{Index: 2, Object: make([]byte, 40)}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSegment(spoolID1, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveSegment(spoolID1, 0); err != nil {
		t.Fatalf("second RemoveSegment: %v", err)
	}
	if got := s.Used(); got != afterCreate+190 {
		t.Fatalf("count = %d, want %d", got, afterCreate+190)
	}
	if _, err := s.ReadSegment(spoolID1, 0); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("ReadSegment of a removed segment = %v", err)
	}
	if err := s.Remove(spoolID1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, spoolID1)); !os.IsNotExist(err) {
		t.Fatal("removed entry left on disk")
	}
	if err := s.WriteSegment(spoolID1, Segment{Index: 3, Object: []byte("x")}); !errors.Is(err, ErrNoEntry) {
		t.Errorf("write to a removed entry = %v, want ErrNoEntry", err)
	}
	if err := s.Remove(spoolID1); err != nil {
		t.Errorf("second Remove: %v", err)
	}
	s2, scan := openTestSpool(t, dir)
	if len(scan.Entries) != 1 || scan.Entries[0].Meta.ID != spoolID2 || s2.Used() != s.Used() {
		t.Fatalf("rescan = %+v, count %d, want %d", scan, s2.Used(), s.Used())
	}
	if err := s.Remove(spoolID2); err != nil {
		t.Fatal(err)
	}
	if s.Used() != 0 {
		t.Errorf("count = %d after removing every entry", s.Used())
	}
	// An id freed by Remove can be created again.
	if err := s.CreateEntry(testMeta(spoolID1)); err != nil {
		t.Errorf("CreateEntry after Remove: %v", err)
	}
}

func TestSpoolMetaValidation(t *testing.T) {
	s, _ := openTestSpool(t, spoolDir(t))
	for name, mutate := range map[string]func(*Meta){
		"policy":       func(m *Meta) { m.Policy = "sometimes" },
		"key":          func(m *Meta) { m.KeySHA256 = m.KeySHA256[:31] },
		"dek":          func(m *Meta) { m.WrappedDEK = nil },
		"device":       func(m *Meta) { m.Identifier = "" },
		"start":        func(m *Meta) { m.LastAcceptedAt = time.Time{} },
		"acked past":   func(m *Meta) { m.Acked = 1 },
		"hash count":   func(m *Meta) { m.Sealed = 1 },
		"acked chain":  func(m *Meta) { m.Sealed, m.Acked = 1, 1 },
		"hash length":  func(m *Meta) { m.Sealed, m.Hashes = 1, [][]byte{{1}} },
		"chain no ack": func(m *Meta) { m.AckedChain = make([]byte, 32) },
	} {
		m := testMeta(spoolID1)
		mutate(&m)
		if err := s.CreateEntry(m); !errors.Is(err, ErrMeta) {
			t.Errorf("%s: CreateEntry = %v, want ErrMeta", name, err)
		}
	}
	if err := s.WriteMeta(testMeta(spoolID1)); !errors.Is(err, ErrNoEntry) {
		t.Errorf("WriteMeta of an unknown entry = %v, want ErrNoEntry", err)
	}
	if s.Used() != 0 {
		t.Errorf("refused creates left a count of %d", s.Used())
	}
}

func TestSpoolConcurrentEntries(t *testing.T) {
	dir := spoolDir(t)
	s, _ := openTestSpool(t, dir)
	ids := []string{spoolID1, spoolID2}
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := testMeta(id)
			if err := s.CreateEntry(m); err != nil {
				t.Error(err)
				return
			}
			for i := uint32(0); i < 20; i++ {
				m = sealedMeta(m, byte(i))
				if err := s.WriteSegment(id, Segment{Index: i, Object: make([]byte, 64)}); err != nil {
					t.Error(err)
				}
				if err := s.WriteMeta(m); err != nil {
					t.Error(err)
				}
				if i%2 == 0 {
					if err := s.RemoveSegment(id, i); err != nil {
						t.Error(err)
					}
				}
			}
		}()
	}
	wg.Wait()
	used := s.Used()
	s2, scan := openTestSpool(t, dir)
	if len(scan.Entries) != 2 || len(scan.Dropped) != 0 || s2.Used() != used {
		t.Fatalf("rescan = %d entries, %d dropped, count %d want %d", len(scan.Entries), len(scan.Dropped), s2.Used(), used)
	}
}
