package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"pgregory.net/rapid"
)

// The state machine's requests (protocol_events.als: ask, matchLive, fromConfig) and their answers (notifAllow, windowAllow,
// refuse)

var (
	caps   = []string{capVM, capConsole, capToken, capFolder, capBus}
	leases = []string{"", "lock", "PT1H", "PT1H", "PT10M", "standing"}
	// A call's: once only there
	callLeases = []string{"", "", "once", "once", "lock", "PT10M"}
	reasons    = []string{"to read the notes", " spaced \n\tout\x07 ", "<b>Allow</b> &amp; trust me", "\x1b[31mred",
		strings.Repeat("é", 2*maxReason)}
)

func (mc *machine) drawParams(t *rapid.T, c string) string {
	kv := map[string]any{}
	switch c {
	case capVM, capConsole:
		kv["name"] = rapid.SampledFrom([]string{"a", "a", "b", "c"}).Draw(t, "name")
	case capToken:
		kv["scope"] = rapid.SampledFrom([]string{"read", "write"}).Draw(t, "scope")
		// Opaque, past what a plain string may be
		if csr := rapid.SampledFrom([]string{"", "", strings.Repeat("A", maxParam+1), strings.Repeat("B", maxOpaque)}).
			Draw(t, "csr"); csr != "" {
			kv["csr"] = csr
		}
	case capFolder:
		kv["path"] = rapid.SampledFrom([]string{mc.w.root + "/x", mc.w.root + "/x", mc.w.root + "/w", mc.w.outside}).Draw(t,
			"path")
	}
	if c == capVM || c == capFolder {
		switch rapid.SampledFrom([]int{0, 0, 0, 1, 2}).Draw(t, "ro") {
		case 1:
			kv["ro"] = true
		case 2:
			kv["ro"] = false
		}
	}
	return params(kv)
}

// Request: one request from inside, of any type, lease and reason. Callers are anonymous: a grant is the sandbox's
func (mc *machine) Request(t *rapid.T) {
	c := rapid.SampledFrom(caps).Draw(t, "capability")
	p := mc.drawParams(t, c)
	lease := rapid.SampledFrom(leases).Draw(t, "lease")
	mc.request(t, mc.w.anonymous(), c, p, lease, rapid.SampledFrom(reasons).Draw(t, "reason"), 1, false)
}

// Call: a host command's call, run under a grant that covers it, or asking for one (once: for that call only)
func (mc *machine) Call(t *rapid.T) {
	p := mc.drawParams(t, capToken)
	lease := rapid.SampledFrom(callLeases).Draw(t, "lease")
	mc.request(t, mc.w.anonymous(), capToken, p, lease, rapid.SampledFrom(reasons).Draw(t, "reason"), 1, true)
}

// Flood: the same request several times at once from one process (P14: one question)
func (mc *machine) Flood(t *rapid.T) {
	c := rapid.SampledFrom(caps).Draw(t, "capability")
	p := mc.drawParams(t, c)
	lease := rapid.SampledFrom(leases).Draw(t, "lease")
	mc.request(t, mc.w.anonymous(), c, p, lease, reasons[0], rapid.IntRange(2, 6).Draw(t, "copies"), false)
}

// Crafted: what the sandbox may send that never reaches the user (P3, P7): an unknown capability, parameters the
// capability doesn't take, of the wrong type or with control characters, no reason, a lease that isn't one
func (mc *machine) Crafted(t *rapid.T) {
	r := rapid.SampledFrom([]request{
		{Capability: "other", Params: json.RawMessage(`{"name":"a"}`), Reason: "x"},
		{Capability: capConsole, Params: json.RawMessage(`{"name":"../a"}`), Reason: "x"},
		{Capability: capConsole, Params: json.RawMessage(`{}`), Reason: "x"},
		{Capability: capConsole, Params: json.RawMessage(`{"name":"a"}`), Reason: "x", Lease: "session"},
		{Capability: capVM, Params: json.RawMessage(`{"name":"a","unit":"evil"}`), Reason: "x"},
		{Capability: capVM, Params: json.RawMessage(`{"name":5}`), Reason: "x"},
		{Capability: capVM, Params: json.RawMessage(`{"name":"a\nAllowed"}`), Reason: "x"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"` + strings.Repeat("w", maxParam+1) + `"}`), Reason: "x"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read","csr":"` + strings.Repeat("C", maxOpaque+1) + `"}`), Reason: "x"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read","csr":"MIIB\nAllowed"}`), Reason: "x"},
		{Capability: capToken, Params: json.RawMessage(`["scope"]`), Reason: "x"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`), Reason: " \n\x07\t "},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`), Reason: "x", Lease: "forever"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`), Reason: "x", Lease: "PT0S"},
		{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`), Reason: "x", Lease: "once"},
		{Op: "call", Capability: capToken, Command: "other", Params: json.RawMessage(`{"scope":"read"}`), Reason: "x"},
		{Op: "call", Capability: capToken, Command: "issue", Params: json.RawMessage(`{"scope":"read"}`),
			Arguments: json.RawMessage(`{"extra":1}`), Reason: "x"},
		{Op: "call", Capability: capVM, Command: "issue", Params: json.RawMessage(`{"name":"a"}`), Reason: "x"},
	}).Draw(t, "crafted")
	if r.Op == "" {
		r.Op = "request"
	}
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
	defer done()
	if res := mc.b.handleRequest(nil, pr, r); res.Error == "" {
		mc.fatalf(t, "Crafted request %+v served: %+v", r, res.Grant)
	}
}

// predict is what request or call does: refuse it, serve a live grant, grant a standing grant, or ask
func (mc *machine) predict(c, p, lease string, call bool) (string, *refGrant) {
	m := mc.m
	lease = leaseOf(lease)
	switch {
	case c == capFolder && !m.shared, !m.leaseOK(lease), !m.passes(c, p, mc.w.root), lease == "once" && !call:
		return "refused", nil
	}
	if g := m.matching(c, p); g != nil {
		return "live", g
	}
	if m.isStanding(c, p) {
		return "standing", nil
	}
	if g := m.gate(c); g.asking || m.now.Before(g.blockedUntil) {
		return "refused", nil
	}
	return "ask", nil
}

func (mc *machine) request(t *rapid.T, who *caller, c, p, lease, reason string, copies int, call bool) {
	mc.tags++
	req := request{Op: "request", Capability: c, Params: json.RawMessage(p), Lease: lease,
		Reason: fmt.Sprintf("why%d: %s", mc.tags, reason)}
	if call {
		req.Op, req.Command, req.Arguments = "call", "issue", json.RawMessage(`{}`)
	}
	kind, live := mc.predict(c, p, lease, call)
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
			mc.fatalf(t, "Request %s %s %s neither answered nor asked", c, p, lease)
		}
	}
	if kind == "ask" && len(calls) != 1 || kind != "ask" && len(calls) != 0 {
		mc.fatalf(t, "Request %s %s %s (%s) asked the user %d times", c, p, lease, kind, len(calls))
	}
	switch kind {
	case "refused":
		for _, res := range results {
			if res.Error == "" {
				mc.fatalf(t, "Request %s %s %s served: %+v", c, p, lease, res.Grant)
			}
		}
	case "live":
		for _, res := range results {
			mc.delivered(t, live, res, call)
		}
	case "standing":
		if !mc.m.lockFree(c, p) {
			for _, res := range results {
				if res.Error == "" {
					mc.fatalf(t, "Standing grant %s %s served with its instance granted elsewhere", c, p)
				}
			}
			return
		}
		if results[0].Grant == nil {
			mc.fatalf(t, "Standing grant %s %s not granted: %s", c, p, results[0].Error)
		}
		g, _ := mc.m.grant(results[0].Grant.ID, c, p, "standing")
		for _, res := range results {
			mc.delivered(t, g, res, call)
		}
	case "ask":
		for _, res := range results {
			if res.Error == "" {
				mc.fatalf(t, "A second request of %s %s served while the first waits", c, p)
			}
		}
		mc.asked(t, calls[0], req, dones[slices.Index(answered, false)])
	}
}

// delivered checks a request's grant, and a call's output: run under the grant, with its validity (P10)
func (mc *machine) delivered(t *rapid.T, g *refGrant, res response, call bool) {
	if res.Error != "" || res.Grant == nil || res.Grant.ID != g.id {
		mc.fatalf(t, "Grant %s %s not delivered: %s %+v", g.cap, g.params, res.Error, res.Grant)
	}
	if !call {
		if res.Output != "" {
			mc.fatalf(t, "Request of %s %s ran something: %q", g.cap, g.params, res.Output)
		}
		// A host socket's grant names its stable address
		want := filepath.Join(mc.w.cfg.SandboxGrantDir, socketsDir, capConsole, fmt.Sprint(decode(g.params)["name"]))
		if g.cap == capConsole && res.Grant.Socket != want {
			mc.fatalf(t, "Console grant %s at %q, want %q", g.params, res.Grant.Socket, want)
		}
		return
	}
	var in callInput
	if err := json.Unmarshal([]byte(res.Output), &in); err != nil {
		mc.fatalf(t, "Call output %q: %v", res.Output, err)
	}
	if want := formatDuration(mc.m.validity(g)); in.Validity != want || string(in.Bounding) != g.params ||
		in.Grant != g.id {
		mc.fatalf(t, "Call run with %s %s under %s, want %s %s", in.Bounding, in.Validity, in.Grant, g.params, want)
	}
}

// leaseOf is the lease a request or call proposes
func leaseOf(lease string) string {
	if lease == "" {
		return defaultLease
	}
	return lease
}

// asked checks the question the user was asked (P7: the daemon's summary, the reason cleaned) and notes it pending
func (mc *machine) asked(t *rapid.T, call *askCall, req request, done chan response) {
	lease := leaseOf(req.Lease)
	tag, _, _ := strings.Cut(req.Reason, " ")
	desc := mc.caps[req.Capability].Description
	// A capability without parameters is its description alone
	named := strings.HasPrefix(call.p.Summary, desc+" (") || string(req.Params) == "{}" && call.p.Summary == desc
	if call.p.Reason != cleanReason(req.Reason) || !named ||
		strings.Contains(call.p.Summary, tag) || call.p.Lease != lease || !call.p.Options {
		mc.fatalf(t, "Asked %+v for %+v", call.p, req)
	}
	p := &refPending{tag: tag, cap: req.Capability, params: string(req.Params), lease: lease,
		asked: mc.m.now, call: call, done: done, isCall: req.Op == "call"}
	mc.b.mu.Lock()
	for id, q := range mc.b.pending {
		if q.Reason == call.p.Reason {
			p.id = id
		}
	}
	mc.b.mu.Unlock()
	mc.m.pending = append(mc.m.pending, p)
	mc.m.gate(req.Capability).asking = true
}
