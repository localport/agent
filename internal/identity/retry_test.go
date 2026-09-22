package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A 4xx other than 429 is a refusal and is not retried.
func TestRetryClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not an error", nil, false},
		{"dial failure", errors.New("dial tcp: connection refused"), true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"500", &APIError{Status: http.StatusInternalServerError}, true},
		{"502", &APIError{Status: http.StatusBadGateway}, true},
		{"503", &APIError{Status: http.StatusServiceUnavailable}, true},
		{"429 is the one retryable 4xx", &APIError{Status: http.StatusTooManyRequests}, true},
		{"400 is terminal", &APIError{Status: http.StatusBadRequest}, false},
		{"401 is terminal", &APIError{Status: http.StatusUnauthorized}, false},
		{"403 is terminal", &APIError{Status: http.StatusForbidden}, false},
		{"404 is terminal", &APIError{Status: http.StatusNotFound}, false},
		{"409 is terminal", &APIError{Status: http.StatusConflict}, false},
		// Context errors are omitted. http.Client.Timeout also reports
		// DeadlineExceeded, and retry decides to stop from ctx. See
		// TestRetryStopsWhenTheCallerCancels.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryable(tc.err); got != tc.want {
				t.Fatalf("isRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Wrapped errors classify the same as unwrapped ones.
func TestRetryClassificationSeesThroughWrapping(t *testing.T) {
	wrapped := errors.Join(errors.New("while renewing"), &APIError{Status: http.StatusForbidden})
	if isRetryable(wrapped) {
		t.Fatal("a wrapped 403 must stay terminal")
	}
}

// A budget of zero is what CI asks for with --wait 0.
func TestZeroBudgetMakesExactlyOneAttempt(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 0, nil, func() error {
		attempts++
		return errors.New("unreachable")
	})
	if err == nil {
		t.Fatal("want the transport error back")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want exactly 1", attempts)
	}
}

// A terminal error must not consume the budget, whatever --wait says.
func TestTerminalErrorIgnoresTheBudget(t *testing.T) {
	attempts := 0
	start := time.Now()
	err := retry(context.Background(), time.Hour, nil, func() error {
		attempts++
		return &APIError{Status: http.StatusForbidden, Message: "spent"}
	})
	if err == nil {
		t.Fatal("want the refusal back")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a refused token must fail immediately, not sit for an hour", attempts)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a terminal error waited; --wait must apply only to retryable conditions")
	}
}

func TestRetrySucceedsAfterATransientFailure(t *testing.T) {
	attempts := 0
	err := retry(context.Background(), 30*time.Second, nil, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("connection reset")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

// Cancellation must win over a pending wait, so Ctrl-C is honoured.
func TestRetryStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()

	err := retry(ctx, time.Hour, nil, func() error { return errors.New("unreachable") })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// Jitter must actually vary and stay inside the bound.
func TestJitterIsBoundedAndVaries(t *testing.T) {
	const d = time.Second
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		got := jitter(d)
		if got < 0 || got > d {
			t.Fatalf("jitter(%s) = %s, outside [0, %s]", d, got, d)
		}
		seen[got] = true
	}
	if len(seen) < 50 {
		t.Fatalf("jitter produced %d distinct values in 200 draws", len(seen))
	}
	if jitter(0) != 0 {
		t.Fatal("jitter(0) must be 0")
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"5", 5 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"nonsense", 0},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Fatalf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
	// An HTTP-date in the future resolves to a positive delay; one in the past
	// resolves to zero so a stale header cannot park the agent.
	if got := parseRetryAfter(time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)); got <= 0 {
		t.Fatalf("a future HTTP-date must yield a positive delay, got %s", got)
	}
	if got := parseRetryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)); got != 0 {
		t.Fatalf("a past HTTP-date must yield 0, got %s", got)
	}
}

// A hostile or misconfigured server must not be able to park the agent past the
// budget it was given.
func TestRetryAfterIsClampedToTheBudget(t *testing.T) {
	attempts := 0
	start := time.Now()
	err := retry(context.Background(), 2*time.Second, nil, func() error {
		attempts++
		return &APIError{Status: http.StatusTooManyRequests, retryAfter: 24 * time.Hour}
	})
	if err == nil {
		t.Fatal("want the 429 back once the budget is spent")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a Retry-After beyond the budget ends the attempt", attempts)
	}
	if time.Since(start) > time.Second {
		t.Fatal("the agent waited on an out-of-budget Retry-After")
	}
}

// A client timeout is retried. http.Client.Timeout matches
// context.DeadlineExceeded, so retry must not stop on the error alone.
func TestRetryKeepsTryingWhenTheControlPlaneHangs(t *testing.T) {
	// Released before srv.Close(), which waits on outstanding handlers.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := &Client{BaseURL: srv.URL, HTTP: &http.Client{Timeout: 100 * time.Millisecond}}

	// The second attempt is refused, which ends the loop. The budget is wide
	// to absorb full jitter.
	attempts := 0
	err := retry(context.Background(), time.Minute, nil, func() error {
		attempts++
		if attempts > 1 {
			return &APIError{Path: "/v1/mtls/certs", Status: http.StatusForbidden}
		}
		return c.post(context.Background(), "/v1/mtls/certs", "tok", map[string]string{}, nil)
	})
	if err == nil {
		t.Fatal("want the refusal that ended the loop")
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2: the request timeout must be retried", attempts)
	}
}

// retry stops when the caller cancels.
func TestRetryStopsWhenTheCallerCancels(t *testing.T) {
	// Released before srv.Close(), which waits on outstanding handlers.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := &Client{BaseURL: srv.URL, HTTP: &http.Client{Timeout: 100 * time.Millisecond}}
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := retry(ctx, 5*time.Second, nil, func() error {
		attempts++
		cancel()
		return c.post(ctx, "/v1/mtls/certs", "tok", map[string]string{}, nil)
	})
	if err == nil {
		t.Fatal("want the attempt's error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

// A refused credential is not retried.
func TestRetryDoesNotRetryARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"TK003","message":"token is invalid"}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: &http.Client{Timeout: time.Second}}
	attempts := 0
	err := retry(context.Background(), 5*time.Second, nil, func() error {
		attempts++
		return c.post(context.Background(), "/v1/mtls/certs", "tok", map[string]string{}, nil)
	})
	if err == nil {
		t.Fatal("want the refusal returned")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1: a 4xx is terminal", attempts)
	}
}

// The control plane client requires TLS 1.3 and keeps the default transport
// proxy and pooling settings.
func TestControlPlaneClientRequiresTLS13(t *testing.T) {
	c, err := NewClient("https://api.localport.io")
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.HTTP.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("TLSClientConfig = %+v, want MinVersion TLS 1.3", tr.TLSClientConfig)
	}
	if tr.Proxy == nil {
		t.Error("Proxy was dropped: a proxied network could no longer reach the control plane")
	}
	if c.HTTP.Timeout != requestTimeout {
		t.Errorf("Timeout = %v, want %v", c.HTTP.Timeout, requestTimeout)
	}
}
