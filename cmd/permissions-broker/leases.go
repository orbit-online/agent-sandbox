package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func (b *broker) now() time.Time { return b.clock.now() }

func (b *broker) checkLease(lease string, sess *session) error {
	switch lease {
	case "session":
		if sess == nil {
			return errors.New("No Claude Code session found above the caller, so no session lease: ask for a duration")
		}
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
		if _, err := parseDuration(lease); err != nil {
			return fmt.Errorf("Lease %q: session, lock, a duration such as PT1H, or once for a call", lease)
		}
	}
	return nil
}

// grant makes a grant live: starts a service's unit and ties it to its lease
func (b *broker) grant(c *capability, params json.RawMessage, summary, reason, lease string, sess *session) (*grant, error) {
	unlock, err := c.exclusiveLock(context.Background(), b.cfg.Launcher, params)
	if err != nil {
		return nil, err
	}
	g := &grant{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Reason: reason, Lease: lease,
		Granted: b.now(), cap: c, ended: make(chan struct{}), unlock: unlock, sessions: map[string]*session{},
		sessGone: make(chan struct{})}
	if lease == "session" {
		g.sessions[sess.id], g.Sessions = sess, []string{sess.id}
	}
	if d, err := parseDuration(lease); err == nil {
		g.Expires = g.Granted.Add(d)
	}
	if c.Type == "service" {
		host := filepath.Join(b.cfg.GrantDir, g.ID+".sock")
		if err := c.startServe(b.cfg.Launcher, g.ID, host, b.cfg.Unit, params); err != nil {
			unlock()
			return nil, err
		}
		g.Socket = filepath.Join(b.cfg.SandboxGrantDir, g.ID+".sock")
	}
	if c.Type == "attach" {
		if err := b.attachGrant(g); err != nil {
			unlock()
			return nil, err
		}
	}
	stopWatch, watchDone, err := c.startWatch(params)
	if err != nil {
		switch c.Type {
		case "service":
			_ = stopServe(b.cfg.Launcher, g.ID)
		case "attach":
			b.detachGrant(g)
		}
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
			stopWatch()
			switch c.Type {
			case "service":
				if err := stopServe(b.cfg.Launcher, g.ID); err != nil {
					slog.Warn("Revoke", "grant", g.ID, "err", err)
				}
			case "attach":
				b.detachGrant(g)
				b.recordHeld(g, why)
			}
			b.mu.Lock()
			for id, s := range g.sessions {
				unix.Close(s.pidfd)
				delete(g.sessions, id)
			}
			b.mu.Unlock()
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
	// Under b.mu, before anyone can find the grant: a session hold adds later watches its own
	for _, s := range g.sessions {
		go b.watchSession(g, s)
	}
	b.mu.Unlock()
	go b.lease(g, watchDone)
	if c.glob != "" {
		go b.watchInstance(g)
	}
	slog.Info("Granted", "grant", g.ID, "capability", g.Capability, "lease", lease)
	b.event("granted", g.ID)
	return g, nil
}

// lease ends g when its time runs out, its session's anchor exits, or its plugin's watch exits. Lock leases end
// through lockEvent
func (b *broker) lease(g *grant, watchDone <-chan struct{}) {
	var timeout <-chan time.Time
	if !g.Expires.IsZero() {
		timeout = b.clock.after(g.Expires.Sub(b.now()))
	}
	select {
	case <-timeout:
		g.end("its time ran out")
	case <-g.sessGone:
		g.end("its sessions ended")
	case <-watchDone:
		g.end("its plugin's watch ended")
	case <-g.ended:
	}
}

// hold records that a caller of sess (nil: no session found) was given g: a release from a session drops its hold
// only, and the grant ends on release once nobody holds it. The hold lasts until the session releases g or its anchor
// exits, so g takes sess's pidfd: returns whether it did
func (b *broker) hold(g *grant, sess *session) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if sess == nil {
		g.anon = true
		return false
	}
	if _, ok := g.sessions[sess.id]; ok || g.over || g.Lease == "session" && len(g.sessions) == 0 {
		// Known, or the grant is ending: a session lease's last session left
		return false
	}
	g.sessions[sess.id] = sess
	g.Sessions = append(g.Sessions, sess.id)
	go b.watchSession(g, sess)
	return true
}

// watchSession drops s's hold on g when its anchor exits, and closes g.sessGone when it was a session lease's last
func (b *broker) watchSession(g *grant, s *session) {
	fds := []unix.PollFd{{Fd: int32(s.pidfd), Events: unix.POLLIN}}
	for {
		// Wakes every few seconds to notice the grant ending otherwise
		n, err := unix.Poll(fds, 5000)
		select {
		case <-s.dropped:
			unix.Close(s.pidfd)
			return
		default:
		}
		select {
		case <-g.ended:
			return
		default:
		}
		if n > 0 {
			break
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if g.sessions[s.id] != s {
		return
	}
	unix.Close(s.pidfd)
	delete(g.sessions, s.id)
	g.Sessions = slices.DeleteFunc(g.Sessions, func(id string) bool { return id == s.id })
	if g.Lease == "session" && len(g.sessions) == 0 {
		close(g.sessGone)
	}
}

// lockEvent ends every lock lease: the screen locked or the machine went to sleep
func (b *broker) lockEvent(why string) {
	for _, g := range b.liveGrants("") {
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

// release drops sess's hold on a grant, and ends it once nobody holds it: no session, nor (but for a session lease) a
// caller without one. A caller without a session ends it outright: that only takes access away. A standing grant
// released so stays ended until the daemon starts again
func (b *broker) release(id string, sess *session, why string) error {
	b.mu.Lock()
	g, ok := b.grants[id]
	if !ok {
		b.mu.Unlock()
		return fmt.Errorf("No grant %q", id)
	}
	if sess != nil {
		g.Sessions = slices.DeleteFunc(g.Sessions, func(id string) bool { return id == sess.id })
		if s, ok := g.sessions[sess.id]; ok {
			delete(g.sessions, sess.id)
			close(s.dropped)
		}
		if len(g.sessions) > 0 || g.anon && g.Lease != "session" {
			b.mu.Unlock()
			slog.Info("Released by a session", "grant", g.ID, "session", sess.id)
			b.event("released", g.ID)
			return nil
		}
	}
	b.mu.Unlock()
	b.endStanding(g)
	g.end(why)
	return nil
}

func (b *broker) endAll(why string) {
	for _, g := range b.liveGrants("") {
		g.end(why)
	}
}

var durationRe = regexp.MustCompile(`^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$`)

// parseDuration reads the ISO 8601 durations leases use: PT1H, PT30M, PT1H30M
func parseDuration(s string) (time.Duration, error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil || s == "PT" {
		return 0, fmt.Errorf("Not a duration such as PT1H: %q", s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{time.Hour, time.Minute, time.Second} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1])
			d += time.Duration(n) * unit
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("Not a positive duration: %q", s)
	}
	return d, nil
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return fmt.Sprintf("PT%dS", int(d.Round(time.Second)/time.Second))
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
