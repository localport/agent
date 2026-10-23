package session

import (
	"sync"
	"time"
)

// fakeClock is a manual clock. Fire sends on the newest timer's channel.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []chan time.Time
	armed  chan struct{} // receives one value per NewTimer
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, armed: make(chan struct{}, 64)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(time.Duration) (<-chan time.Time, func() bool) {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.timers = append(c.timers, ch)
	c.mu.Unlock()
	c.armed <- struct{}{}
	return ch, func() bool { return true }
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
