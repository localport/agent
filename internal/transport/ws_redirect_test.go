package transport

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The upgrade client must not follow a 3xx to the Location host.
func TestWSDoesNotFollowRedirect(t *testing.T) {
	var followed atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Add(1)
	}))
	defer elsewhere.Close()
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer edge.Close()

	resp, err := wsHTTPClient(http.DefaultTransport).Get(edge.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want the 307 itself", resp.StatusCode)
	}
	if n := followed.Load(); n != 0 {
		t.Fatalf("the redirect was followed %d times", n)
	}
}
