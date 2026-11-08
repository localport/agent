package recording

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testFailedOpen(id string) FailedOpen {
	return FailedOpen{ID: id, SessionID: id, Identifier: testMeta(id).Identifier, KeySHA256: make([]byte, 32), Reason: ReasonSpoolFull}
}

func failedQueueLen(f *uploaderFixture) int {
	f.u.mu.Lock()
	defer f.u.mu.Unlock()
	return len(f.u.failed)
}

func waitFailedBackoff(t *testing.T, f *uploaderFixture) {
	t.Helper()
	waitFor(t, "failed open backoff", func() bool {
		f.u.mu.Lock()
		defer f.u.mu.Unlock()
		return len(f.u.failed) == 1 && !f.u.failed[0].busy && !f.u.failed[0].next.IsZero()
	})
}

func TestFailedOpenIsSentOnceAndForgotten(t *testing.T) {
	f := startUploader(t, false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	c := f.edge.expect(t, "failed", spoolID1, 0)
	if c.reason != ReasonSpoolFull {
		t.Fatalf("reason %q", c.reason)
	}
	ok(c, 0)
	waitFor(t, "queue empty", func() bool { return failedQueueLen(f) == 0 })
	f.edge.expectNone(t)
}

// Past the bound the oldest report is dropped and logged.
func TestFailedOpenQueueDropsTheOldest(t *testing.T) {
	f := startUploader(t, false)
	f.edge.up.Store(false)
	for i := range maxFailedOpens + 1 {
		f.u.ReportFailedOpen(testFailedOpen(fmt.Sprintf("id-%d", i)))
	}
	f.u.mu.Lock()
	n, oldest := len(f.u.failed), f.u.failed[0].ID
	f.u.mu.Unlock()
	if n != maxFailedOpens || oldest != "id-1" {
		t.Fatalf("queue %d entries, oldest %s; want %d, id-1", n, oldest, maxFailedOpens)
	}
	if !strings.Contains(f.logs.String(), "id-0") {
		t.Fatalf("the evicted report was not logged: %s", f.logs.String())
	}
}

// A report outlives a mux loss and goes out on the next mux.
func TestFailedOpenSurvivesAMuxLoss(t *testing.T) {
	f := startUploader(t, false)
	f.edge.up.Store(false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	waitFailedBackoff(t, f)
	f.edge.up.Store(true)
	f.u.ClientUp(testMeta(spoolID1).Identifier)
	ok(f.edge.expect(t, "failed", spoolID1, 0), 0)
}

// Busy and unavailable back off from 1 s, honouring retry_after, and the
// backoff caps at 30 s.
func TestFailedOpenBacksOffWhileBusy(t *testing.T) {
	f := startUploader(t, false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	refuse(f.edge.expect(t, "failed", spoolID1, 0), http.StatusServiceUnavailable, CodeBusy, 0)
	waitFailedBackoff(t, f)
	f.clock.Advance(time.Second - time.Nanosecond)
	f.edge.expectNone(t)
	f.clock.Advance(time.Nanosecond)
	refuse(f.edge.expect(t, "failed", spoolID1, 0), http.StatusServiceUnavailable, CodeUnavailable, 5*time.Second)
	waitFor(t, "second backoff", func() bool {
		f.u.mu.Lock()
		defer f.u.mu.Unlock()
		return !f.u.failed[0].busy && f.u.failed[0].attempt == 2
	})
	f.clock.Advance(5*time.Second - time.Nanosecond)
	f.edge.expectNone(t)
	f.clock.Advance(time.Nanosecond)
	f.edge.expect(t, "failed", spoolID1, 0)
}

// Any other refusal ends the report.
func TestFailedOpenStopsOnARefusal(t *testing.T) {
	f := startUploader(t, false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	refuse(f.edge.expect(t, "failed", spoolID1, 0), http.StatusGone, CodeClosed, 0)
	waitFor(t, "queue empty", func() bool { return failedQueueLen(f) == 0 })
	f.edge.expectNone(t)
}

// A report the edge can no longer attest is dropped ten minutes after queuing.
func TestFailedOpenExpires(t *testing.T) {
	f := startUploader(t, false)
	f.edge.up.Store(false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	waitFailedBackoff(t, f)
	f.clock.Advance(failedOpenLifetime)
	waitFor(t, "queue empty", func() bool { return failedQueueLen(f) == 0 })
}

// A failed open never overtakes a control request already running for the
// device, and the report is dropped when the uploader stops.
func TestFailedOpenWaitsForTheDeviceControlRequest(t *testing.T) {
	f := startUploader(t, false)
	h := f.begin(t, spoolID1, PolicyBestEffort)
	if err := h.End(Completion{EndedAt: fixtureStart, Final: true}); err != nil {
		t.Fatal(err)
	}
	complete := f.edge.expect(t, "complete", spoolID1, 0)
	f.u.ReportFailedOpen(testFailedOpen(spoolID2))
	f.edge.expectNone(t)
	ok(complete, 0)
	f.edge.expect(t, "failed", spoolID2, 0)
	f.stop()
	if n := failedQueueLen(f); n != 0 {
		t.Fatalf("%d reports after the stop", n)
	}
}

// The backoff is capped.
func TestFailedOpenBackoffCap(t *testing.T) {
	f := startUploader(t, false)
	f.u.ReportFailedOpen(testFailedOpen(spoolID1))
	refuse(f.edge.expect(t, "failed", spoolID1, 0), http.StatusServiceUnavailable, CodeBusy, 0)
	waitFailedBackoff(t, f)
	f.u.mu.Lock()
	r := result{failed: f.u.failed[0], err: &Refusal{Status: http.StatusServiceUnavailable, Code: CodeBusy}}
	r.failed.attempt = 40
	f.u.control[r.failed.Identifier]++
	f.u.applyFailedOpenLocked(r)
	wait := r.failed.next.Sub(f.u.now())
	f.u.mu.Unlock()
	if wait != failedOpenMaxBackoff {
		t.Fatalf("backoff %v, want %v", wait, failedOpenMaxBackoff)
	}
}
