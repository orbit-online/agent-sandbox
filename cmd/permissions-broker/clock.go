package main

import "time"

// clock is the broker's time and the timers leases and answers wait on. Tests replace it with a fake one they advance
type clock interface {
	now() time.Time
	after(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) now() time.Time                         { return time.Now() }
func (realClock) after(d time.Duration) <-chan time.Time { return time.After(d) }
