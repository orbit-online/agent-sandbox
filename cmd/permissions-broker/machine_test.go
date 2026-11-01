package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Stateful property tests: rapid runs random sequences of the protocol model's actions (models/protocol_events.als,
// protocol_system.als) against the real broker in a sandbox stand-in, and Check (machine_check_test.go) compares the
// broker's state, its store file and the window's view with the reference (machine_model_test.go) after every step.
// The actions are in machine_requests_test.go, machine_answers_test.go and machine_actions_test.go, the world they run
// in in machine_world_test.go. Not here: the notification's own checks (forge, mature: notify_test.go), commands
// waiting for a plugin slot (TestNoOutputAfterEnd), renames beneath a ceiling (attach_test.go, swap_test.go) and the
// sandbox's end.
//
// The package build runs 50 sequences; more with -rapid.checks=1000 -rapid.steps=100 (or RAPID_CHECKS and
// RAPID_STEPS), a failure again with -rapid.seed or -rapid.failfile as rapid prints them.
func TestBrokerMachine(t *testing.T) {
	f := newFixture(t)
	rapidDefault(t, "rapid.checks", "50")
	rapid.Check(t, func(rt *rapid.T) {
		actions := rapid.StateMachineActions(newMachine(rt, f))
		// Weights: Repeat picks actions evenly
		for _, a := range []string{"Request", "Request", "Request", "NotifyAllow", "WindowAnswer", "Share", "LockWatched",
			"Restart", "Instances"} {
			actions[a+strconv.Itoa(len(actions))] = actions[a]
		}
		rt.Repeat(actions)
	})
}

// rapidDefault sets a rapid flag for this test unless the command line or the environment did
func rapidDefault(t *testing.T, name, value string) {
	set := os.Getenv(strings.ToUpper(strings.ReplaceAll(name, ".", "_"))) != ""
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	if set {
		return
	}
	old := flag.Lookup(name).Value.String()
	_ = flag.Set(name, value)
	t.Cleanup(func() { _ = flag.Set(name, old) })
}

type machine struct {
	w    *world
	m    *model
	b    *broker
	clk  *fakeClock
	view *clockView // the daemon's
	n    *notifier
	caps map[string]*capability
	ev   *events
	tags int
	// The other launcher's exclusive locks
	otherLocks map[string]func()
}

func newMachine(t *rapid.T, f *fixture) *machine {
	w := newWorld(t, f)
	mc := &machine{w: w, clk: newFakeClock(), caps: w.capabilities(), ev: &events{ended: map[string]bool{}},
		otherLocks: map[string]func(){}}
	mc.m = newModel(mc.clk.now(), w.cfg.Grants)
	mc.setListed([]string{"a", "b"})
	mc.startBroker(t)
	t.Cleanup(func() { mc.b.endAll("test over") })
	return mc
}

// startBroker starts a daemon as run does, without serving the sockets: requests come straight to the handlers. It
// grants the standing grants that pass the ceiling and the exclusive locks, in the config's order (P12)
func (mc *machine) startBroker(t *rapid.T) {
	mc.n = &notifier{calls: make(chan *askCall, 8)}
	b, err := newBroker(mc.w.cfg, mc.caps, mc.w.sb, mc.n.ask)
	if err != nil {
		mc.w.t.Fatal(err)
	}
	mc.view = mc.clk.view()
	b.clock = mc.view
	mc.b = b
	mc.watch()
	before := mc.grantedCount()
	reqLn, ctlLn, err := b.start()
	if err != nil {
		mc.w.t.Fatal(err)
	}
	reqLn.Close()
	ctlLn.Close()
	made, m := mc.grantedSince(before), mc.m
	n := 0
	for _, k := range m.standing {
		if !m.passes(k.cap, k.params, mc.w.root) || !m.lockFree(k.cap, k.params) {
			continue
		}
		if n == len(made) {
			mc.fatalf(t, "Standing grant %v not granted at start: made %v", k, made)
		}
		m.grant(made[n], k.cap, k.params, "standing", "")
		n++
	}
	if n != len(made) {
		mc.fatalf(t, "Grants made at start %v, want %d", made, n)
	}
}

func (mc *machine) setListed(names []string) {
	mc.w.setInstances([]*capability{mc.caps[capVM], mc.caps[capConsole]}, names)
	clear(mc.m.listed)
	for _, n := range names {
		mc.m.listed[n] = true
	}
}

// events records the broker's watch events: the grants made, in order, and those ended, once their end is done
type events struct {
	mu      sync.Mutex
	ch      chan []byte
	granted []string
	ended   map[string]bool
}

// watch subscribes to the broker's events, as a watch stream does
func (mc *machine) watch() {
	mc.ev.ch = make(chan []byte, 4096)
	mc.b.mu.Lock()
	mc.b.watches[mc.ev.ch] = true
	mc.b.mu.Unlock()
}

// drain takes the events sent so far, under ev.mu
func (ev *events) drain() {
	for {
		select {
		case line := <-ev.ch:
			var e struct{ Event, ID string }
			_ = json.Unmarshal(line, &e)
			switch e.Event {
			case "granted":
				ev.granted = append(ev.granted, e.ID)
			case "ended":
				ev.ended[e.ID] = true
			}
		default:
			return
		}
	}
}

func (mc *machine) grantedSince(n int) []string {
	mc.ev.mu.Lock()
	defer mc.ev.mu.Unlock()
	mc.ev.drain()
	return slices.Clone(mc.ev.granted[n:])
}

func (mc *machine) grantedCount() int {
	mc.ev.mu.Lock()
	defer mc.ev.mu.Unlock()
	mc.ev.drain()
	return len(mc.ev.granted)
}

var hexID = regexp.MustCompile(`\b[0-9a-f]{16}\b`)

// fatalf fails with the same message whenever rapid replays the case, which it needs to minimise it: the iteration's
// directory and the broker's random ids left out, grants named by the order they were made
func (mc *machine) fatalf(t *rapid.T, format string, args ...any) {
	t.Helper()
	msg := strings.ReplaceAll(fmt.Sprintf(format, args...), mc.w.dir, "…")
	t.Fatal(hexID.ReplaceAllStringFunc(msg, func(id string) string {
		if g := mc.m.grants[id]; g != nil {
			return "g" + strconv.Itoa(g.seq)
		}
		return "<id>"
	}))
}

// waitFor waits until cond holds
func (mc *machine) waitFor(t *rapid.T, what string, cond func() bool) {
	for deadline := time.Now().Add(settle); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			mc.fatalf(t, "Waited for %s", what)
		}
	}
}

// waitEnded waits until the grants ended: gone from the broker, their units stopped and mounts detached
func (mc *machine) waitEnded(t *rapid.T, ids ...string) {
	for _, id := range ids {
		mc.waitFor(t, "the end of grant "+id, func() bool {
			mc.ev.mu.Lock()
			defer mc.ev.mu.Unlock()
			mc.ev.drain()
			return mc.ev.ended[id]
		})
	}
}

// waitDone waits for a pending request's caller to get its answer
func (mc *machine) waitDone(t *rapid.T, p *refPending) response {
	select {
	case res := <-p.done:
		return res
	case <-time.After(settle):
		mc.fatalf(t, "Request %s (%s %s) not answered", p.tag, p.cap, p.params)
		return response{}
	}
}
