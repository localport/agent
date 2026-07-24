package ui

import (
	"io"
	"sync"
	"testing"

	"github.com/localport/agent/internal/tunnel"
)

func TestPlainRequestCounts(t *testing.T) {
	p := NewPlain()
	p.out = io.Discard
	defer p.Shutdown()

	p.OnHTTPRequest("t", tunnel.RequestInfo{Status: 200})
	p.OnHTTPRequest("t", tunnel.RequestInfo{Status: 404}) // warn
	p.OnHTTPRequest("t", tunnel.RequestInfo{Status: 503}) // error

	p.mu.Lock()
	s := p.stats["t"]
	p.mu.Unlock()
	if s == nil || s.requests != 3 || s.warns != 1 || s.errors != 1 {
		t.Fatalf("counts = %+v", s)
	}
}

// TestPlainRequestLogConcurrent exercises the emit path from many goroutines at
// once (as many forwarding goroutines would) to prove the counts stay accurate
// and the decoupled logging neither races nor deadlocks. Run under -race.
func TestPlainRequestLogConcurrent(t *testing.T) {
	p := NewPlain()
	p.out = io.Discard
	defer p.Shutdown()

	const goroutines, each = 8, 500
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				p.OnHTTPRequest("t", tunnel.RequestInfo{Status: 200})
			}
		}()
	}
	wg.Wait()

	p.mu.Lock()
	got := p.stats["t"].requests
	p.mu.Unlock()
	if want := int64(goroutines * each); got != want {
		t.Fatalf("requests = %d, want %d", got, want)
	}
}
