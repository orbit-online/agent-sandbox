package main

import (
	"sync"
	"time"
)

// fakeClock is a clock tests advance by hand: its timers fire when it passes their time
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	timers []fakeTimer
	// How many timers were asked for, by duration
	made map[time.Duration]int
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), made: map[time.Duration]int{}}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.made[d]++
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- c.t
	} else {
		c.timers = append(c.timers, fakeTimer{at: c.t.Add(d), ch: ch})
	}
	return ch
}

// advance moves the time on and fires the timers due
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	kept := c.timers[:0]
	for _, t := range c.timers {
		if t.at.After(c.t) {
			kept = append(kept, t)
		} else {
			t.ch <- c.t
		}
	}
	c.timers = kept
}

// jump moves the time on without firing timers: they're late
func (c *fakeClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// drop forgets every timer, which then never fires: their daemon died
func (c *fakeClock) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timers = nil
}

// asked is how many timers of d were asked for
func (c *fakeClock) asked(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.made[d]
}
