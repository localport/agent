package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func testUser(login string, uid uint32) *userRecord {
	return &userRecord{Name: login, UID: uid, GID: uid, Groups: []uint32{uid}, Home: "/home/" + login, Shell: "/bin/sh"}
}

// eventLog collects a server's OnEvent lines.
type eventLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *eventLog) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}

func (l *eventLog) has(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func lookupServer(t *testing.T) (*kindServer, *eventLog) {
	t.Helper()
	events := &eventLog{}
	ts := newTestKindServer(t, func(c *ServerConfig) { c.OnEvent = events.add })
	return ts, events
}

// Each lookup refusal comes before the spend, releases the slot and logs its
// reason.
func TestServeRefusesOnTheUserLookupUnspent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		euid   int
		lookup func(context.Context, string) (*userRecord, error)
		code   string
		logged string
	}{
		{"no account", 0, func(context.Context, string) (*userRecord, error) { return nil, errNoUser }, CodeLoginNotAllowed, "no such user"},
		{"lookup failure", 0, func(context.Context, string) (*userRecord, error) {
			return nil, errors.New("getent passwd exited with status 3")
		}, CodeAgentBusy, "status 3"},
		{"lookup timeout", 0, func(ctx context.Context, _ string) (*userRecord, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, CodeAgentBusy, "deadline exceeded"},
		{"not root, another login", 1000, func(_ context.Context, login string) (*userRecord, error) {
			return testUser(login, 1001), nil
		}, CodeLoginNotAllowed, "not the agent's own user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, events := lookupServer(t)
			ts.users, ts.euid = tc.lookup, func() int { return tc.euid }
			if got := ts.refusal(t, ts.ticket(t, nil)); got != tc.code {
				t.Fatalf("refused %q, want %q", got, tc.code)
			}
			if ts.spent(ts.f.payload().JTI) {
				t.Fatal("the refused ticket is spent")
			}
			if n := ts.LiveSessions(); n != 0 {
				t.Fatalf("%d slots held after the refusal, want 0", n)
			}
			if !events.has(tc.logged) {
				t.Fatalf("no log line with %q in %v", tc.logged, events.lines)
			}
		})
	}
}

// The kind receives the resolved account: any account when the agent is
// root, its own when it is not.
func TestServePassesTheResolvedUserToTheKind(t *testing.T) {
	for _, tc := range []struct {
		name string
		euid int
		uid  uint32
	}{
		{"root", 0, 1001},
		{"not root, own login", 1000, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, _ := lookupServer(t)
			want := testUser("pi", tc.uid)
			ts.users = func(_ context.Context, login string) (*userRecord, error) {
				if login != "pi" {
					t.Errorf("looked up %q, want the ticket's pi", login)
				}
				return want, nil
			}
			ts.euid = func() int { return tc.euid }
			c := ts.open(t, ts.ticket(t, nil))
			if k := ts.kind(t); k.user != want {
				t.Fatalf("kind user %+v, want %+v", k.user, want)
			}
			c.conn.Close()
			waitDone(t, c.done)
		})
	}
}

// One deadline covers the lookup: at most 2 s, and never past the first-frame
// time less the reserve; with no time left the lookup does not start.
func TestResolveUserDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		elapsed time.Duration
		left    time.Duration // want the deadline about this far away; 0 means refused
	}{
		{"fresh stream", 0, userLookupTimeout},
		{"late stream", 6 * time.Second, firstFrameTimeout - userLookupReserve - 6*time.Second},
		{"no time left", firstFrameTimeout - userLookupReserve, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, events := lookupServer(t)
			var deadline time.Time
			called := false
			ts.users = func(ctx context.Context, login string) (*userRecord, error) {
				called = true
				deadline, _ = ctx.Deadline()
				return testUser(login, 1000), nil
			}
			now := time.Now()
			user, code := ts.resolveUser("pi", now.Add(-tc.elapsed))
			if tc.left == 0 {
				if code != CodeAgentBusy || called || !events.has("no time left") {
					t.Fatalf("code %q, lookup called %v; want agent_busy without a lookup, logged", code, called)
				}
				return
			}
			if code != "" || user == nil {
				t.Fatalf("code %q, want the user", code)
			}
			// resolveUser reads the clock just after now.
			if d := deadline.Sub(now); d > tc.left+100*time.Millisecond || d < tc.left-time.Second {
				t.Fatalf("deadline %v away, want about %v", d, tc.left)
			}
		})
	}
}
