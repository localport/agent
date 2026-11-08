package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A build with no launcher refuses a session kind it cannot serve.
func TestLocalRefusalWithoutALauncher(t *testing.T) {
	s := &Server{cfg: ServerConfig{Capabilities: []string{"terminal"}}}
	err := s.localRefusal(&admission{Kind: "terminal", Login: "pi"})
	if err == nil || !strings.Contains(err.Error(), "this build serves no session") {
		t.Fatalf("localRefusal = %v", err)
	}
}

// A Shutdown cancels a key refresh in flight, on both refresh paths, and a
// refresh that starts during a Shutdown is already cancelled.
func TestShutdownEndsAKeyRefresh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refresh func(s *Server)
	}{
		{"recording key", func(s *Server) { s.recordingKeyMatches("no-such-key") }},
		{"unknown CA", func(s *Server) {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			caKey, _ := ssh.NewPublicKey(pub)
			_, _ = s.withCARefresh(&ssh.Certificate{SignatureKey: caKey}, func() (*admission, error) { return nil, errors.New("unknown CA") })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := make(chan struct{})
			finished := make(chan error, 1)
			var s *Server
			cfg := ServerConfig{
				RecordingKey: func() ([]byte, [sha256.Size]byte, bool) { return nil, [sha256.Size]byte{}, false },
				RefreshKeys: func(ctx context.Context) error {
					close(entered)
					<-ctx.Done()
					finished <- ctx.Err()
					return ctx.Err()
				},
			}
			s = NewServer(cfg)
			done := make(chan struct{})
			go func() { tc.refresh(s); close(done) }()
			<-entered
			if err := s.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-finished:
				if err != context.Canceled {
					t.Fatalf("refresh ended with %v, want cancelled at once", err)
				}
			case <-time.After(keyRefreshTimeout / 2):
				t.Fatal("the refresh outlasted the Shutdown")
			}
			<-done
			s.mu.Lock()
			left := len(s.refreshes)
			s.mu.Unlock()
			if left != 0 {
				t.Fatalf("%d refreshes still registered", left)
			}
		})
	}
}
