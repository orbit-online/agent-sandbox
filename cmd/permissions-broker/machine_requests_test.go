package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"pgregory.net/rapid"
)

// The state machine's requests (protocol_events.als: ask, matchLive, fromConfig) and their answers (notifAllow, windowAllow,
// refuse), drawn from the declarations (machine_gen_test.go) and judged by the oracle (machine_judge_test.go)

// shape is what the machine's requests are drawn from: instances' names from the world's, folders beneath the
// ceiling's roots and around them
func (mc *machine) shape() requestShape {
	return requestShape{caps: mc.m.caps, ids: slices.Sorted(maps.Keys(mc.caps)),
		callIDs: []string{capToken, capToken, capToken, capVM}, hint: mc.hint}
}

func (mc *machine) hint(t *rapid.T, id, arg string) (string, bool) {
	switch {
	case arg == "name" && (id == capVM || id == capConsole):
		name := rapid.SampledFrom(mc.names).Draw(t, "instance")
		if !often(t, 8, "known instance") {
			name = drawInstanceName(t)
		}
		return encodeString(t, name), true
	case arg == "path" && id == capFolder:
		root := mc.w.root
		return encodeString(t, drawPath(t, []string{root, root, root + "/x", root + "/w", mc.w.outside, mc.w.dir})), true
	}
	return "", false
}

// Request: one request from inside, of any type, lease and reason. Callers are anonymous: a grant is the sandbox's
func (mc *machine) Request(t *rapid.T) {
	mc.tags++
	mc.request(t, mc.w.anonymous(), mc.shape().draw(t, false, fmt.Sprintf("why%d", mc.tags)), 1)
}

// Call: a host command's call, run under a grant that covers it, or asking for one (once: for that call only)
func (mc *machine) Call(t *rapid.T) {
	mc.tags++
	mc.request(t, mc.w.anonymous(), mc.shape().draw(t, true, fmt.Sprintf("why%d", mc.tags)), 1)
}

// Flood: the same request or call several times at once from one process (P14: one question)
func (mc *machine) Flood(t *rapid.T) {
	mc.tags++
	req := mc.shape().draw(t, rapid.Bool().Draw(t, "call"), fmt.Sprintf("why%d", mc.tags))
	mc.request(t, mc.w.anonymous(), req, rapid.IntRange(2, 6).Draw(t, "copies"))
}

func (mc *machine) request(t *rapid.T, who *caller, req wire.Request, copies int) {
	call := req.Op == "call"
	v := mc.m.judge(call, req.Capability, req.Command, req.Params, req.Arguments, req.Reason, req.Lease)
	about := fmt.Sprintf("%s %q %s %s %q", req.Op, req.Capability, req.Params, req.Arguments, req.Lease)
	dones := make([]chan response, copies)
	finished := make(chan int, copies)
	for i := range dones {
		dones[i] = make(chan response, 1)
		pr, closePeer := mc.w.peerOfPid(who.pid)
		go func() {
			res := mc.b.handleRequest(nil, pr, req)
			closePeer()
			dones[i] <- res
			finished <- i
		}()
	}
	var calls []*askCall
	var results []response
	answered := make([]bool, copies)
	for len(calls)+len(results) < copies {
		select {
		case i := <-finished:
			answered[i] = true
			results = append(results, <-dones[i])
		case call := <-mc.n.calls:
			calls = append(calls, call)
		case <-time.After(settle):
			mc.fatalf(t, "%s neither answered nor asked", about)
		}
	}
	if v.kind == "ask" && len(calls) != 1 || v.kind != "ask" && len(calls) != 0 {
		mc.fatalf(t, "%s (%s %v) asked the user %d times", about, v.kind, v.broken, len(calls))
	}
	switch {
	case v.refused():
		for _, res := range results {
			if !refusedAs(res, v) {
				mc.fatalf(t, "%s: %q (%s), want refused as one of %v", about, res.Error, res.Refused, v.broken)
			}
		}
	case v.kind == "live":
		for _, res := range results {
			mc.delivered(t, v.grant, res, call, req.Arguments)
		}
	case v.kind == "standing":
		if !mc.m.lockFree(req.Capability, v.vals) {
			for _, res := range results {
				if res.Refused != refHeld {
					mc.fatalf(t, "Standing grant %s %s served with its instance granted elsewhere: %+v", req.Capability,
						v.params, res)
				}
			}
			return
		}
		if results[0].Grant == nil {
			mc.fatalf(t, "Standing grant %s %s not granted: %s", req.Capability, v.params, results[0].Error)
		}
		g, _ := mc.m.grant(results[0].Grant.ID, req.Capability, v.params, "standing")
		for _, res := range results {
			mc.delivered(t, g, res, call, req.Arguments)
		}
	case v.kind == "ask":
		for _, res := range results {
			if res.Refused != refAsking {
				mc.fatalf(t, "A second %s served while the first waits: %+v", about, res)
			}
		}
		mc.asked(t, calls[0], req, v, dones[slices.Index(answered, false)])
	}
}

// delivered checks a request's grant, and a call's run: under the grant, with its bounding values and arguments as
// sent, and its validity (P10)
func (mc *machine) delivered(t *rapid.T, g *refGrant, res response, call bool, args json.RawMessage) {
	if res.Error != "" || res.Grant == nil || res.Grant.ID != g.id {
		mc.fatalf(t, "Grant %s %s not delivered: %s %+v", g.cap, g.params, res.Error, res.Grant)
	}
	if !call {
		if res.Output != "" {
			mc.fatalf(t, "Request of %s %s ran something: %q", g.cap, g.params, res.Output)
		}
		// A host socket's grant names its stable address
		want := filepath.Join(mc.w.cfg.SandboxGrantDir, socketsDir, capConsole, fmt.Sprint(g.vals["name"]))
		if g.cap == capConsole && res.Grant.Socket != want {
			mc.fatalf(t, "Console grant %s at %q, want %q", g.params, res.Grant.Socket, want)
		}
		return
	}
	var in hostcmd.Input
	if err := json.Unmarshal([]byte(res.Output), &in); err != nil {
		mc.fatalf(t, "Call output %q: %v", res.Output, err)
	}
	if want := duration.Format(mc.m.validity(g)); in.Validity != want || canonical(objectOf(in.Bounding)) != g.params ||
		in.Grant != g.id {
		mc.fatalf(t, "Call run with %s %s under %s, want %s %s", in.Bounding, in.Validity, in.Grant, g.params, want)
	}
	if got, want := canonical(objectOf(in.Arguments)), canonical(objectOf(args)); got != want {
		mc.fatalf(t, "Call run with arguments %s, want %s", got, want)
	}
}

// asked checks the question the user was asked (P7: the daemon's summary, the reason folded) and notes it pending
func (mc *machine) asked(t *rapid.T, call *askCall, req wire.Request, v verdict, done chan response) {
	tag, _, _ := strings.Cut(req.Reason, ":")
	c := mc.caps[req.Capability]
	// A host command capability's summary is its consent title and the bounding values, without parentheses
	desc, open := c.Description, " ("
	if c.Type == "command" {
		desc, open = c.Title, " "
	}
	// A capability without parameters is its description alone
	named := strings.HasPrefix(call.p.Summary, desc+open) || len(v.vals) == 0 && call.p.Summary == desc ||
		req.Capability == capFolder && strings.HasPrefix(call.p.Summary, desc)
	leaked := strings.HasPrefix(tag, "why") && strings.Contains(call.p.Summary, tag)
	if call.p.Reason != oracleReason(req.Reason) || !named || leaked || call.p.Lease != v.lease || !call.p.Options {
		mc.fatalf(t, "Asked %+v for %+v", call.p, req)
	}
	p := &refPending{tag: tag, cap: req.Capability, params: v.params, vals: v.vals, lease: v.lease, asked: mc.m.now,
		call: call, done: done, isCall: req.Op == "call", args: req.Arguments}
	known := map[string]bool{}
	for _, q := range mc.m.pending {
		known[q.id] = true
	}
	mc.b.mu.Lock()
	for id := range mc.b.pending {
		if !known[id] {
			p.id = id
		}
	}
	mc.b.mu.Unlock()
	mc.m.pending = append(mc.m.pending, p)
	mc.m.gate(req.Capability).asking = true
}
