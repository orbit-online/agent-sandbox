package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
)

func (b *broker) now() time.Time { return b.clock.now() }

func (b *broker) checkLease(lease string) error {
	switch lease {
	case "once":
		// obtain lets only calls ask for it
	case "lock":
		b.mu.Lock()
		ok := b.lockOK
		b.mu.Unlock()
		if !ok {
			return errors.New("Screen lock isn't watched, so no lock lease: ask for a duration")
		}
	default:
		if _, err := duration.Parse(lease); err != nil {
			return fmt.Errorf("Lease %q: lock, a duration such as PT1H, or once for a call", lease)
		}
	}
	return nil
}

// grant makes a grant live, as its capability's kind does (mounts a folder, gives a host socket its address, adds a
// D-Bus rule set to its proxy), and ties it to its lease
func (b *broker) grant(c *capability, params json.RawMessage, summary, reason, lease string) (*grant, error) {
	unlock, err := c.exclusiveLock(b.cfg.Launcher, params)
	if err != nil {
		return nil, err
	}
	g := &grant{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Reason: reason, Lease: lease,
		Granted: b.now(), cap: c, ended: make(chan struct{}), unlock: unlock}
	if d, err := duration.Parse(lease); err == nil {
		g.Expires = g.Granted.Add(d)
	}
	if err := c.kind().live(b, g); err != nil {
		unlock()
		return nil, err
	}
	var once sync.Once
	g.end = func(why string) {
		once.Do(func() {
			b.mu.Lock()
			delete(b.grants, g.ID)
			g.over = true
			b.mu.Unlock()
			b.closeConns(g)
			c.kind().end(b, g, why)
			g.unlock()
			close(g.ended)
			slog.Info("Grant ended", "grant", g.ID, "capability", g.Capability, "why", why)
			b.event("ended", g.ID)
		})
	}
	// A lock lease only while the lock is watched: checked under b.mu, so lockSignals losing the bus either finds the
	// grant to end or makes this refuse it
	b.mu.Lock()
	if lease == "lock" && !b.lockOK {
		b.mu.Unlock()
		g.end("the screen lock isn't watched")
		return nil, errors.New("Screen lock isn't watched any more, so no lock lease: ask for a duration")
	}
	b.grants[g.ID] = g
	b.mu.Unlock()
	go b.lease(g)
	if c.glob != "" {
		go b.watchInstance(g)
	}
	slog.Info("Granted", "grant", g.ID, "capability", g.Capability, "lease", lease)
	b.event("granted", g.ID)
	return g, nil
}

// lease ends g when its time runs out. Lock leases end through lockEvent
func (b *broker) lease(g *grant) {
	if g.Expires.IsZero() {
		return
	}
	select {
	case <-b.clock.after(g.Expires.Sub(b.now())):
		g.end("its time ran out")
	case <-g.ended:
	}
}

// lockEvent ends every lock lease: the screen locked or the machine went to sleep
func (b *broker) lockEvent(why string) {
	for _, g := range b.liveGrants() {
		if g.Lease == "lock" {
			g.end(why)
		}
	}
}

// revoke ends a grant for the user and returns what still held files on it (attach grants). A standing grant stays
// ended until the daemon starts again
func (b *broker) revoke(id string) ([]holder, error) {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("No grant %q", id)
	}
	b.endStanding(g)
	g.end("revoked by the user")
	return g.Holders, nil
}

// release ends a grant from inside: that only takes access away. A standing grant released so stays ended until the
// daemon starts again
func (b *broker) release(id, why string) error {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("No grant %q", id)
	}
	b.endStanding(g)
	g.end(why)
	return nil
}

func (b *broker) endAll(why string) {
	for _, g := range b.liveGrants() {
		g.end(why)
	}
}

// watchLogind ends lock leases when the graphical session locks or the machine sleeps. The watch is set up before it
// returns, and serve calls it before b.run, so no request finds lock leases refused because the watch is still being
// set up; the signals are then read in a goroutine. Lock leases are refused if setup fails
func watchLogind(b *broker, setup func() (<-chan *dbus.Signal, string, error)) {
	signals, session, err := setup()
	if err != nil {
		slog.Warn("No lock leases", "err", err)
		return
	}
	b.mu.Lock()
	b.lockOK = true
	b.mu.Unlock()
	slog.Info("Watching the screen lock", "session", session)
	go b.lockSignals(signals)
}

// logindSignals subscribes to the lock and sleep signals and returns them with the graphical session's ID. The daemon
// runs in a user unit, outside any login session, so it finds the user's graphical session through user/self's Display
// property; logind sends no signals on the self aliases
func logindSignals() (<-chan *dbus.Signal, string, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, "", fmt.Errorf("Connect to the system bus: %w", err)
	}
	user := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1/user/self")
	var display struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := user.StoreProperty("org.freedesktop.login1.User.Display", &display); err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("Find the graphical session: %w", err)
	}
	if display.Path == "/" || display.Path == "" {
		conn.Close()
		return nil, "", errors.New("No graphical session")
	}
	matches := []dbus.MatchOption{dbus.WithMatchObjectPath(display.Path)}
	for _, m := range [][]dbus.MatchOption{
		append(matches, dbus.WithMatchInterface("org.freedesktop.DBus.Properties")),
		append(matches, dbus.WithMatchInterface("org.freedesktop.login1.Session"), dbus.WithMatchMember("Lock")),
		{dbus.WithMatchObjectPath("/org/freedesktop/login1"), dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
			dbus.WithMatchMember("PrepareForSleep")},
	} {
		if err := conn.AddMatchSignal(m...); err != nil {
			conn.Close()
			return nil, "", err
		}
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	return signals, display.ID, nil
}

// lockSignals ends lock leases on the signals until the bus goes, then refuses lock leases and ends those there
func (b *broker) lockSignals(signals <-chan *dbus.Signal) {
	for s := range signals {
		switch s.Name {
		case "org.freedesktop.login1.Session.Lock":
			b.lockEvent("the screen locked")
		case "org.freedesktop.login1.Manager.PrepareForSleep":
			if len(s.Body) == 1 && s.Body[0] == true {
				b.lockEvent("the machine went to sleep")
			}
		case "org.freedesktop.DBus.Properties.PropertiesChanged":
			if len(s.Body) >= 2 {
				if changed, ok := s.Body[1].(map[string]dbus.Variant); ok {
					if v, ok := changed["LockedHint"]; ok && v.Value() == true {
						b.lockEvent("the screen locked")
					}
				}
			}
		}
	}
	b.mu.Lock()
	b.lockOK = false
	b.mu.Unlock()
	b.lockEvent("the screen lock isn't watched any more")
	slog.Warn("No lock leases", "err", "Lost the system bus")
}
