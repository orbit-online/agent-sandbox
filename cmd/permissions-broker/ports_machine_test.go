package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// A port the machine asks for, and the one of them its config grants standing
var (
	machinePorts = []string{"tcp-1", "tcp-2", "udp-1"}
	standingPort = "udp-1"
)

func portParams(p string) json.RawMessage {
	var proto string
	var port int
	_, _ = fmt.Sscanf(p[:3]+" "+p[4:], "%s %d", &proto, &port)
	return json.RawMessage(fmt.Sprintf(`{"port":%d,"protocol":%q}`, port, proto))
}

// portMachine drives the port capability through the actions models/protocol has for it (P18): requests answered,
// releases and revokes, time passing, the helper failing to grant, to print the addresses, to revoke or to revoke them
// all and recovering, a crash with its cleanup and a start. Its own state is the model's, the oracle after every step:
// the ports the helper has on are those of the live grants and at most the closing ones, which the broker tracks, and
// once the helper revokes again every closing port goes off
type portMachine struct {
	t   *testing.T
	p   peer
	b   *broker
	f   *fakeAsker
	nk  fakeNetkit
	clk *fakeClock
	cv  *clockView
	// The model: live grants by port, with their expiry (zero for standing) and id; the ports whose revoke failed,
	// closing; the standing grant ended; the gate of the capability; the helper failing to grant, to print the addresses,
	// to revoke, and to revoke all
	live             map[string]time.Time
	ids              map[string]string
	closing          map[string]bool
	standingOver     bool
	refused          int
	blockedUntil     time.Time
	failing          bool
	addrFailing      bool
	revokeFailing    bool
	revokeAllFailing bool
}

func TestPortMachine(t *testing.T) {
	p := peerAt(t, os.Getpid())
	retries := revokeRetries
	revokeRetries = []time.Duration{0, 0}
	t.Cleanup(func() { revokeRetries = retries })
	rapid.Check(t, func(rt *rapid.T) {
		b, f, nk := portBroker(t)
		b.cfg.Grants = []standingConfig{{Capability: portID, Params: portParams(standingPort)}}
		m := &portMachine{t: t, p: p, f: f, nk: nk, clk: newFakeClock()}
		m.start(rt, b.cfg, b.caps, b.sb)
		rt.Repeat(rapid.StateMachineActions(m))
	})
}

// start is a daemon starting: it grants the standing port
func (m *portMachine) start(rt *rapid.T, cfg config, caps map[string]*capability, sb *sandbox) {
	b, err := newBroker(cfg, caps, sb, m.f.ask)
	if err != nil {
		rt.Fatal(err)
	}
	m.cv = m.clk.view()
	b.clock = m.cv
	b.grantStanding()
	m.b = b
	m.live, m.ids, m.closing = map[string]time.Time{standingPort: {}}, map[string]string{}, map[string]bool{}
	m.standingOver, m.refused, m.blockedUntil = false, 0, time.Time{}
	m.syncIDs()
}

// syncIDs learns the grant ids of the live ports from the broker
func (m *portMachine) syncIDs() {
	for _, g := range m.b.liveGrants() {
		for _, p := range machinePorts {
			if string(g.Params) == string(portParams(p)) {
				m.ids[p] = g.ID
			}
		}
	}
}

func (m *portMachine) Request(rt *rapid.T) {
	p := rapid.SampledFrom(machinePorts).Draw(rt, "port")
	allow := rapid.Bool().Draw(rt, "allow")
	minutes := rapid.IntRange(1, 3).Draw(rt, "minutes")
	m.f.mu.Lock()
	m.f.answers = []string{map[bool]string{true: "allow", false: "deny"}[allow]}
	m.f.mu.Unlock()
	g, err := m.b.request(m.p, req(portID, string(portParams(p)), fmt.Sprintf("PT%dM", minutes)))
	now := m.clk.now()
	_, live := m.live[p]
	var want refusal
	switch {
	case live:
	case p == standingPort && !m.standingOver:
		want = m.grant(p, time.Time{})
	case now.Before(m.blockedUntil):
		want = refBlocked
	case !allow:
		want = refDenied
		if m.refused++; m.refused >= maxRefusals {
			m.refused, m.blockedUntil = 0, now.Add(blockFor)
		}
	default:
		m.refused = 0
		want = m.grant(p, now.Add(time.Duration(minutes)*time.Minute))
	}
	if refusalOf(err) != want {
		rt.Fatalf("Request %s: %v, want %q", p, err, want)
	}
	if err == nil {
		m.ids[p] = g.ID
		// Switched on again: no longer closing
		delete(m.closing, p)
	}
}

// grant is the live of a grant of p that isn't live: made, or failed with its port off, or closing when the helper
// switched it on, failed to print the addresses and fails to revoke it
func (m *portMachine) grant(p string, exp time.Time) refusal {
	switch {
	case m.failing:
		return refFailed
	case m.addrFailing:
		m.off(p)
		return refFailed
	}
	m.live[p] = exp
	return ""
}

// off is the end of the grant of p: its port closing while the helper fails to revoke
func (m *portMachine) off(p string) {
	delete(m.live, p)
	if m.revokeFailing {
		m.closing[p] = true
	}
}

func (m *portMachine) end(rt *rapid.T, revoke bool) {
	ps := slices.Sorted(maps.Keys(m.live))
	if len(ps) == 0 {
		return
	}
	p := rapid.SampledFrom(ps).Draw(rt, "port")
	var err error
	if revoke {
		_, err = m.b.revoke(m.ids[p])
	} else {
		err = m.b.release(m.ids[p], "released")
	}
	if err != nil {
		rt.Fatalf("End %s: %v", p, err)
	}
	m.off(p)
	if p == standingPort {
		m.standingOver = true
	}
}

func (m *portMachine) Release(rt *rapid.T) { m.end(rt, false) }
func (m *portMachine) Revoke(rt *rapid.T)  { m.end(rt, true) }

func (m *portMachine) ReleaseNone(rt *rapid.T) {
	if err := m.b.release("made-up", "released"); refusalOf(err) != refNoGrant {
		rt.Fatalf("Release of a grant there isn't: %v", err)
	}
}

func (m *portMachine) Time(rt *rapid.T) {
	m.clk.advance(time.Minute)
	now := m.clk.now()
	for p, exp := range m.live {
		if !exp.IsZero() && !exp.After(now) {
			m.off(p)
		}
	}
}

func (m *portMachine) HelperFails(rt *rapid.T) {
	m.failing = !m.failing
	m.nk.fail(m.t, "grant", m.failing)
}

func (m *portMachine) RevokeFails(rt *rapid.T) {
	m.revokeFailing = !m.revokeFailing
	m.nk.fail(m.t, "revoke", m.revokeFailing)
}

func (m *portMachine) AddrFails(rt *rapid.T) {
	m.addrFailing = !m.addrFailing
	m.nk.fail(m.t, "addr", m.addrFailing)
}

func (m *portMachine) RevokeAllFails(rt *rapid.T) {
	m.revokeAllFailing = !m.revokeAllFailing
	m.nk.fail(m.t, "revoke-all", m.revokeAllFailing)
}

// Recover: the helper revokes again, and time passes until the broker closed every closing port
func (m *portMachine) Recover(rt *rapid.T) {
	if m.revokeFailing {
		m.RevokeFails(rt)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if slices.Equal(m.nk.ports(), slices.Sorted(maps.Keys(m.live))) && len(m.closingOf()) == 0 {
			clear(m.closing)
			return
		}
		if time.Now().After(deadline) {
			rt.Fatalf("Closing after the helper recovered: ports on %v, closing %v", m.nk.ports(), m.closingOf())
		}
		m.Time(rt)
	}
}

// closingOf is what the broker has closing
func (m *portMachine) closingOf() []string {
	m.b.mu.Lock()
	states := maps.Clone(m.b.ports)
	m.b.mu.Unlock()
	var out []string
	for p, s := range states {
		s.mu.Lock()
		if s.closing {
			out = append(out, p)
		}
		s.mu.Unlock()
	}
	slices.Sort(out)
	return out
}

// Crash is the daemon dying, the cleanup of its unit and a new daemon. Nothing of the old one runs on: its timers die,
// and its ports stay locked, so no revoke of a closing port is tried after. While the helper fails to revoke all, the
// cleanup tries again and the ports stay on, until the helper recovers
func (m *portMachine) Crash(rt *rapid.T) {
	m.b.mu.Lock()
	for _, s := range m.b.ports {
		s.mu.Lock()
	}
	m.b.mu.Unlock()
	m.cv.die()
	on := m.nk.ports()
	done := make(chan struct{})
	go func() { cleanup(m.b.cfg, m.b.sb, m.clk); close(done) }()
	if m.revokeAllFailing {
		tries := strings.Count(m.nk.log(), "--all\n")
		for deadline := time.Now().Add(5 * time.Second); strings.Count(m.nk.log(), "--all\n") < tries+2; {
			if time.Now().After(deadline) {
				rt.Fatalf("No second try of the cleanup:\n%s", m.nk.log())
			}
			m.clk.advance(time.Minute)
			time.Sleep(time.Millisecond)
		}
		select {
		case <-done:
			rt.Fatal("The cleanup ended while the helper failed to revoke the ports")
		default:
		}
		if !slices.Equal(m.nk.ports(), on) {
			rt.Fatalf("Ports on while the cleanup fails: %v, want %v", m.nk.ports(), on)
		}
		m.RevokeAllFails(rt)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		select {
		case <-done:
		default:
			if time.Now().After(deadline) {
				rt.Fatal("The cleanup didn't end")
			}
			m.clk.advance(time.Minute)
			continue
		}
		break
	}
	m.start(rt, m.b.cfg, m.b.caps, m.b.sb)
	if _, live := m.live[standingPort]; live && (m.failing || m.addrFailing) {
		delete(m.live, standingPort)
		if !m.failing && m.revokeFailing {
			m.closing[standingPort] = true
		}
	}
}

// Check: the live grants are the model's, every one has its port on, and a port on without one is closing in the
// model and in the broker
func (m *portMachine) Check(rt *rapid.T) {
	want := slices.Sorted(maps.Keys(m.live))
	covered := func(on []string) bool {
		closing := m.closingOf()
		for _, p := range want {
			if !slices.Contains(on, p) {
				return false
			}
		}
		for _, p := range on {
			if _, live := m.live[p]; !live && !(m.closing[p] && slices.Contains(closing, p)) {
				return false
			}
		}
		return true
	}
	// Leases end on timers of their own
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		var live []string
		for _, g := range m.b.liveGrants() {
			for _, p := range machinePorts {
				if string(g.Params) == string(portParams(p)) {
					live = append(live, p)
				}
			}
		}
		slices.Sort(live)
		if covered(m.nk.ports()) && slices.Equal(live, want) {
			return
		}
		if time.Now().After(deadline) {
			rt.Fatalf("Ports on %v, live grants %v, closing %v (broker %v), want %v", m.nk.ports(), live,
				slices.Sorted(maps.Keys(m.closing)), m.closingOf(), want)
		}
	}
}
