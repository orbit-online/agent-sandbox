package main

import (
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

func (b *broker) now() time.Time { return time.Now().Add(time.Duration(b.skew.Load())) }

func (b *broker) checkLease(lease string, sess *session) error {
	switch lease {
	case "always":
	case "session":
		if sess == nil {
			return errors.New("No Claude Code session found above the caller, so no session lease: ask for a duration")
		}
	case "lock":
		b.mu.Lock()
		ok := b.lockOK
		b.mu.Unlock()
		if !ok {
			return errors.New("Screen lock isn't watched, so no lock lease: ask for a duration")
		}
	default:
		if _, err := parseDuration(lease); err != nil {
			return fmt.Errorf("Lease %q: session, lock, always or a duration such as PT1H", lease)
		}
	}
	return nil
}

// validity is how long a type B credential lasts: maxValidity, or a duration lease's remainder if shorter
func (b *broker) validity(c *capability, g *grant) time.Duration {
	v, _ := parseDuration(c.Ceiling.MaxValidity)
	if !g.Expires.IsZero() {
		if left := g.Expires.Sub(b.now()); left < v {
			v = left
		}
	}
	return v
}

// grant makes a grant live: delivers type A and ties it to its lease
func (b *broker) grant(c *capability, params json.RawMessage, summary, lease string, sess *session) (*grant, error) {
	unlock, err := c.exclusiveLock(b.cfg.Launcher, params)
	if err != nil {
		return nil, err
	}
	g := &grant{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Lease: lease,
		Granted: b.now(), cap: c, ended: make(chan struct{}), unlock: unlock, sessions: map[string]*session{},
		sessGone: make(chan struct{})}
	if lease == "session" {
		g.sessions[sess.id], g.Sessions = sess, []string{sess.id}
	}
	if d, err := parseDuration(lease); err == nil {
		g.Expires = g.Granted.Add(d)
	}
	if c.Type == "A" {
		host := filepath.Join(b.cfg.GrantDir, g.ID+".sock")
		if err := c.startServe(b.cfg.Launcher, g.ID, host, b.cfg.Unit, params); err != nil {
			unlock()
			return nil, err
		}
		g.Socket = filepath.Join(b.cfg.SandboxGrantDir, g.ID+".sock")
	}
	if c.Type == "C" {
		if err := b.mountC(g); err != nil {
			unlock()
			return nil, err
		}
	}
	stopWatch, watchDone, err := c.startWatch(params)
	if err != nil {
		switch c.Type {
		case "A":
			_ = stopServe(b.cfg.Launcher, g.ID)
		case "C":
			b.unmountC(g)
		}
		unlock()
		return nil, err
	}
	var once sync.Once
	g.end = func(why string) {
		once.Do(func() {
			b.mu.Lock()
			delete(b.grants, g.ID)
			b.mu.Unlock()
			stopWatch()
			switch c.Type {
			case "A":
				if err := stopServe(b.cfg.Launcher, g.ID); err != nil {
					slog.Warn("Revoke", "grant", g.ID, "err", err)
				}
			case "C":
				b.unmountC(g)
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
	b.mu.Lock()
	b.grants[g.ID] = g
	b.mu.Unlock()
	go b.lease(g, watchDone)
	slog.Info("Granted", "grant", g.ID, "capability", g.Capability, "lease", lease)
	b.event("granted", g.ID)
	return g, nil
}

// lease ends g when its time runs out, its session's anchor exits, or its plugin's watch exits. Lock leases end
// through lockEvent
func (b *broker) lease(g *grant, watchDone <-chan struct{}) {
	var timeout <-chan time.Time
	if !g.Expires.IsZero() {
		t := time.NewTimer(g.Expires.Sub(b.now()))
		defer t.Stop()
		timeout = t.C
	}
	b.mu.Lock()
	for _, s := range g.sessions {
		go b.watchSession(g, s)
	}
	b.mu.Unlock()
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

// addSession ties a session lease to one more session. Returns whether it took the session's pidfd
func (b *broker) addSession(g *grant, s *session) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := g.sessions[s.id]; ok || len(g.sessions) == 0 {
		// Known, or the grant is ending: its last session left
		return false
	}
	g.sessions[s.id] = s
	g.Sessions = append(g.Sessions, s.id)
	go b.watchSession(g, s)
	return true
}

// watchSession drops s from g when its anchor exits, and closes g.sessGone when it was the last
func (b *broker) watchSession(g *grant, s *session) {
	fds := []unix.PollFd{{Fd: int32(s.pidfd), Events: unix.POLLIN}}
	for {
		// Wakes every few seconds to notice the grant ending otherwise
		n, err := unix.Poll(fds, 5000)
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
	if len(g.sessions) == 0 {
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

// revoke ends a grant for the user and returns what still held files on it (type C)
func (b *broker) revoke(id string) ([]holder, error) {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("No grant %q", id)
	}
	g.end("revoked by the user")
	return g.Holders, nil
}

// endHolders ends processes the window lists as holding a revoked grant, if they are in the sandbox
func (b *broker) endHolders(pids []int) error {
	var errs []error
	for _, pid := range pids {
		// Through a pidfd taken before the check, so the pid can't be another process's by the signal
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue // gone already
		}
		if !b.sb.isDescendant(pid) {
			errs = append(errs, fmt.Errorf("%d isn't in the sandbox", pid))
		} else if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, fmt.Errorf("End %d: %w", pid, err))
		}
		unix.Close(fd)
	}
	return errors.Join(errs...)
}

func (b *broker) release(id, why string) error {
	b.mu.Lock()
	g, ok := b.grants[id]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("No grant %q", id)
	}
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

// watchLogind ends lock leases when the graphical session locks or the machine sleeps. The daemon runs in a user
// unit, outside any login session, so it finds the user's graphical session through user/self's Display property;
// logind sends no signals on the self aliases. Lock leases are refused until this is set up
func watchLogind(b *broker) {
	if err := watchLogindErr(b); err != nil {
		slog.Warn("No lock leases", "err", err)
	}
}

func watchLogindErr(b *broker) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("Connect to the system bus: %w", err)
	}
	user := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1/user/self")
	var display struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := user.StoreProperty("org.freedesktop.login1.User.Display", &display); err != nil {
		return fmt.Errorf("Find the graphical session: %w", err)
	}
	if display.Path == "/" || display.Path == "" {
		return errors.New("No graphical session")
	}
	matches := []dbus.MatchOption{dbus.WithMatchObjectPath(display.Path)}
	if err := conn.AddMatchSignal(append(matches, dbus.WithMatchInterface("org.freedesktop.DBus.Properties"))...); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(append(matches, dbus.WithMatchInterface("org.freedesktop.login1.Session"),
		dbus.WithMatchMember("Lock"))...); err != nil {
		return err
	}
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath("/org/freedesktop/login1"),
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"), dbus.WithMatchMember("PrepareForSleep")); err != nil {
		return err
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	b.mu.Lock()
	b.lockOK = true
	b.mu.Unlock()
	slog.Info("Watching the screen lock", "session", display.ID)
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
	return errors.New("Lost the system bus")
}
