package main

import (
	"slices"
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
	at    time.Time
	ch    chan time.Time
	owner *clockView
}

// clockView is a fake clock as one daemon sees it: when that daemon dies, its timers die with it, also those it asks
// for after
type clockView struct {
	c    *fakeClock
	dead bool // under c.mu
}

func (c *fakeClock) view() *clockView { return &clockView{c: c} }

func (v *clockView) now() time.Time { return v.c.now() }

func (v *clockView) after(d time.Duration) <-chan time.Time { return v.c.afterFor(v, d) }

// die forgets the view's timers, which then never fire
func (v *clockView) die() {
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	v.dead = true
	v.c.timers = slices.DeleteFunc(v.c.timers, func(t fakeTimer) bool { return t.owner == v })
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), made: map[time.Duration]int{}}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) after(d time.Duration) <-chan time.Time { return c.afterFor(nil, d) }

func (c *fakeClock) afterFor(owner *clockView, d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if owner != nil && owner.dead {
		return ch
	}
	c.made[d]++
	if d <= 0 {
		ch <- c.t
	} else {
		c.timers = append(c.timers, fakeTimer{at: c.t.Add(d), ch: ch, owner: owner})
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

// asked is how many timers of d were asked for
func (c *fakeClock) asked(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.made[d]
}
