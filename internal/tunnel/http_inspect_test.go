package tunnel

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// inspect feeds request then response bytes through a fresh inspector and
// returns what it emitted. Feeding is synchronous, so results are ready on
// return. Requests are fed before responses, mirroring reality: a response
// cannot exist before its request.
func inspect(reqBytes, respBytes string) []RequestInfo {
	var got []RequestInfo
	in := newHTTPInspector(func(r RequestInfo) { got = append(got, r) })
	in.feedRequest([]byte(reqBytes))
	in.feedResponse([]byte(respBytes))
	return got
}

func req(method, path string, extraHeaders, body string) string {
	return method + " " + path + " HTTP/1.1\r\nHost: x\r\n" + extraHeaders + "\r\n" + body
}

func resp(status, extraHeaders, body string) string {
	return "HTTP/1.1 " + status + "\r\n" + extraHeaders + "\r\n" + body
}

func TestInspectorKeepAlive(t *testing.T) {
	got := inspect(
		req("GET", "/a", "", "")+req("POST", "/b", "Content-Length: 3\r\n", "abc"),
		resp("200 OK", "Content-Length: 2\r\n", "hi")+resp("500 Internal Server Error", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %+v", len(got), got)
	}
	if got[0].Method != "GET" || got[0].Path != "/a" || got[0].Status != 200 {
		t.Errorf("req 0 = %+v", got[0])
	}
	if got[1].Method != "POST" || got[1].Path != "/b" || got[1].Status != 500 {
		t.Errorf("req 1 = %+v", got[1])
	}
}

func TestInspectorNoBodyResponses(t *testing.T) {
	// A 204 carries no body; the scanner must not read into the next response.
	got := inspect(
		req("GET", "/x", "", "")+req("GET", "/y", "", ""),
		resp("204 No Content", "", "")+resp("200 OK", "Content-Length: 1\r\n", "z"),
	)
	if len(got) != 2 || got[0].Status != 204 || got[1].Status != 200 {
		t.Fatalf("no-body handling = %+v", got)
	}
}

func TestInspectorHeadRequest(t *testing.T) {
	// A response to HEAD has Content-Length but no body. Skipping that CL would
	// eat the next response; the scanner must key off the HEAD method instead.
	got := inspect(
		req("HEAD", "/a", "", "")+req("GET", "/b", "", ""),
		resp("200 OK", "Content-Length: 100\r\n", "")+resp("200 OK", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 2 || got[0].Path != "/a" || got[1].Path != "/b" {
		t.Fatalf("HEAD handling = %+v", got)
	}
}

func TestInspectorInterim1xx(t *testing.T) {
	// A 100 Continue precedes the final response and must not consume a request.
	got := inspect(
		req("POST", "/a", "Content-Length: 0\r\n", ""),
		resp("100 Continue", "", "")+resp("200 OK", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 1 || got[0].Status != 200 {
		t.Fatalf("1xx handling = %+v", got)
	}
}

func TestInspectorChunked(t *testing.T) {
	// A chunked response must be skipped correctly so the next one is still read.
	got := inspect(
		req("GET", "/a", "", "")+req("GET", "/b", "", ""),
		resp("200 OK", "Transfer-Encoding: chunked\r\n", "3\r\nabc\r\n0\r\n\r\n")+
			resp("201 Created", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 2 || got[0].Status != 200 || got[1].Status != 201 {
		t.Fatalf("chunked handling = %+v", got)
	}
}

func TestInspectorChunkedSplitAcrossFeeds(t *testing.T) {
	// The same exchange fed one byte at a time exercises every cross-feed
	// boundary in the chunk parser.
	reqBytes := req("GET", "/a", "", "") + req("GET", "/b", "", "")
	respBytes := resp("200 OK", "Transfer-Encoding: chunked\r\n", "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n") +
		resp("201 Created", "Content-Length: 0\r\n", "")

	var got []RequestInfo
	in := newHTTPInspector(func(r RequestInfo) { got = append(got, r) })
	for i := 0; i < len(reqBytes); i++ {
		in.feedRequest([]byte{reqBytes[i]})
	}
	for i := 0; i < len(respBytes); i++ {
		in.feedResponse([]byte{respBytes[i]})
	}
	if len(got) != 2 || got[0].Status != 200 || got[1].Status != 201 {
		t.Fatalf("chunked split feed = %+v", got)
	}
}

func TestInspectorLargeBodySurvives(t *testing.T) {
	// A large Content-Length body must be skipped by count, not buffered, so the
	// next request on the connection is still seen.
	big := strings.Repeat("x", 5<<20) // 5 MiB
	got := inspect(
		req("POST", "/upload", "Content-Length: 5242880\r\n", big)+req("GET", "/after", "", ""),
		resp("200 OK", "Content-Length: 0\r\n", "")+resp("200 OK", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 2 || got[0].Path != "/upload" || got[1].Path != "/after" {
		t.Fatalf("large body = %+v", got)
	}
}

func TestInspectorDropsQueryString(t *testing.T) {
	// A token in the query must never be captured.
	got := inspect(
		req("GET", "/reset?token=SECRET&x=1", "", ""),
		resp("200 OK", "Content-Length: 0\r\n", ""),
	)
	if len(got) != 1 || got[0].Path != "/reset" {
		t.Fatalf("query not dropped: %+v", got)
	}
}

// TestScanReaderForwardStaysExact is the safety property: whatever the scanner
// is fed, the copy through the wrapper delivers the bytes unchanged. The data
// here is not valid HTTP, so the scanner gives up; the forward must not care.
func TestScanReaderForwardStaysExact(t *testing.T) {
	in := newHTTPInspector(func(RequestInfo) {})
	data := make([]byte, 200<<10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	var dst bytes.Buffer
	if _, err := io.Copy(&dst, in.wrapRequest(bytes.NewReader(data))); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst.Bytes(), data) {
		t.Fatalf("wrapper corrupted the forwarded stream")
	}
}

func TestInspectorPendingCapped(t *testing.T) {
	// Requests with no responses (a dead response scanner) must not grow pending
	// without bound.
	in := newHTTPInspector(func(RequestInfo) {})
	var reqs strings.Builder
	for i := 0; i < maxPending*3; i++ {
		reqs.WriteString(req("GET", "/a", "", ""))
	}
	in.feedRequest([]byte(reqs.String()))
	in.mu.Lock()
	n := len(in.pending)
	in.mu.Unlock()
	if n > maxPending {
		t.Fatalf("pending grew to %d, cap is %d", n, maxPending)
	}
}

func TestRecentRequestsRingIsBounded(t *testing.T) {
	tn := &Tunnel{}
	for i := 1; i <= maxRecentRequests+5; i++ {
		tn.recordRequest(RequestInfo{Path: "/", Status: i})
	}
	got := tn.RecentRequests()
	if len(got) != maxRecentRequests {
		t.Fatalf("ring len = %d, want %d", len(got), maxRecentRequests)
	}
	if got[0].Status != 6 || got[len(got)-1].Status != maxRecentRequests+5 {
		t.Errorf("ring window = [%d..%d], want [6..%d]",
			got[0].Status, got[len(got)-1].Status, maxRecentRequests+5)
	}
}

func TestNewRequestInspectorGating(t *testing.T) {
	cases := []struct {
		proto    string
		disabled bool
		want     bool
	}{
		{"http", false, true},
		{"https", false, true},
		{"tcp", false, false},
		{"tls", false, false},
		{"http", true, false},
	}
	for _, tc := range cases {
		tn := &Tunnel{opts: Options{Protocol: tc.proto, DisableInspect: tc.disabled}}
		if got := tn.newRequestInspector() != nil; got != tc.want {
			t.Errorf("proto=%s disabled=%v: present=%v want=%v", tc.proto, tc.disabled, got, tc.want)
		}
	}
}
