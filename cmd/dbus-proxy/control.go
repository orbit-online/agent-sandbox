package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/internal/dbuspolicy"
)

// The control socket (--control): the permissions broker adds and removes live rule sets, one per D-Bus grant, by the
// grant's id. One JSON object a line each way, a request then its answer:
//
//	{"op":"add","id":"<grant>","see":[NAME],"talk":[NAME],"own":[NAME],"call":["NAME=RULE"],"broadcast":["NAME=RULE"]}
//	{"op":"remove","id":"<grant>"}
//	{"ok":true,"closed":<connections ended>} or {"error":"..."}
//
// A set applies from the next message the proxy reads; a removal ends the connections that used the set. One broker
// at a time: when its connection closes, every live set goes as by a removal

const (
	maxControlLine = 64 << 10
	maxLiveSets    = 32
	// Entries in one set, so adding one costs each client a bounded number of the proxy's own calls
	maxSetEntries = 64
)

var setID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type controlRequest struct {
	Op        string   `json:"op"`
	ID        string   `json:"id"`
	See       []string `json:"see"`
	Talk      []string `json:"talk"`
	Own       []string `json:"own"`
	Call      []string `json:"call"`
	Broadcast []string `json:"broadcast"`
}

type controlResponse struct {
	OK     bool   `json:"ok,omitempty"`
	Closed int    `json:"closed,omitempty"`
	Error  string `json:"error,omitempty"`
}

// The live sets by id, which only the connected broker changes
type control struct {
	p    *Proxy
	mu   sync.Mutex
	busy bool
	sets map[string]*RuleSet
}

// Serves the control socket until it's closed
func (p *Proxy) serveControl(l *net.UnixListener) error {
	ctl := &control{p: p, sets: map[string]*RuleSet{}}
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			p.log.Warn("Control accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err := p.controlPeer(conn); err != nil {
			p.log.Warn("Control peer refused", "err", err)
			conn.Close()
			continue
		}
		ctl.mu.Lock()
		busy := ctl.busy
		ctl.busy = true
		ctl.mu.Unlock()
		if busy {
			p.log.Warn("Control peer refused: the broker is connected already")
			conn.Close()
			continue
		}
		go ctl.serve(conn)
	}
}

// The broker: a peer of the proxy's uid, on a socket only the host reaches. The socket is in a 0700 directory under
// $XDG_RUNTIME_DIR/claude-desktop, which nothing binds into the sandbox (the module refuses binds and host sockets
// there), so a peer is a host process of the user's, which reaches the bus without the proxy anyway. The proxy can't
// tell the sandbox's processes apart by more: they have the user's uid, and the kernel refuses a process in a user
// namespace of its own (nixpak's wrapper and the system-bus bwrap make one) the peer's namespaces from its pidfd
// (PIDFD_GET_*_NAMESPACE need ptrace access, which commoncap refuses across user namespaces), and it has no /proc.
// One connection at a time on top: a second while the broker is connected is closed
func (p *Proxy) controlPeer(conn *net.UnixConn) error {
	cred, err := peerCred(conn)
	if err != nil {
		return err
	}
	if int(cred.Uid) != p.uid {
		return fmt.Errorf("Peer uid %d is not the proxy's %d", cred.Uid, p.uid)
	}
	return nil
}

// Answers the broker's requests until its connection ends, then drops every live set
func (ctl *control) serve(conn *net.UnixConn) {
	defer func() {
		conn.Close()
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		for id, rs := range ctl.sets {
			n := ctl.p.removeSet(rs)
			ctl.p.log.Info("Live rule set dropped with the broker's connection", "id", id, "closed", n)
		}
		clear(ctl.sets)
		ctl.busy = false
	}()
	r := bufio.NewReaderSize(conn, maxControlLine)
	enc := json.NewEncoder(conn)
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				_ = enc.Encode(controlResponse{Error: "Request too long"})
			}
			return
		}
		var req controlRequest
		var res controlResponse
		if err := json.Unmarshal(line, &req); err != nil {
			res.Error = "Not a JSON request"
		} else if res.Closed, err = ctl.do(req); err != nil {
			res.Error = err.Error()
		} else {
			res.OK = true
		}
		if err := enc.Encode(res); err != nil {
			return
		}
	}
}

func (ctl *control) do(req controlRequest) (int, error) {
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	if !setID.MatchString(req.ID) {
		return 0, errors.New("An id of 1 to 64 letters, digits, _ and -")
	}
	switch req.Op {
	case "add":
		if ctl.sets[req.ID] != nil {
			return 0, fmt.Errorf("Rule set %s is there already", req.ID)
		}
		if len(ctl.sets) >= maxLiveSets {
			return 0, fmt.Errorf("%d live rule sets at most", maxLiveSets)
		}
		rs, err := parseLiveSet(req, ctl.p.policyBus, ctl.p.appID)
		if err != nil {
			return 0, err
		}
		ctl.sets[req.ID] = rs
		ctl.p.addSet(rs)
		ctl.p.log.Info("Live rule set added", "id", req.ID)
		return 0, nil
	case "remove":
		rs := ctl.sets[req.ID]
		if rs == nil {
			return 0, fmt.Errorf("No rule set %s", req.ID)
		}
		delete(ctl.sets, req.ID)
		n := ctl.p.removeSet(rs)
		ctl.p.log.Info("Live rule set removed", "id", req.ID, "closed", n)
		return n, nil
	}
	return 0, fmt.Errorf("Unknown op %q", req.Op)
}

// A live set from a request, with the command line's syntax. The static guards stay: nothing in a set reaches the bus
// driver, so no monitoring, eavesdropping or bus calls beyond the static ones, and no destination-less calls (those are
// refused before any rule is looked at). And the bus's policy, which the module and the broker check too
// (internal/dbuspolicy): a broker that's confused or a peer that isn't the broker can't add what the config can't
// declare
func parseLiveSet(req controlRequest, bus, appID string) (*RuleSet, error) {
	rs := NewRuleSet()
	rs.id = req.ID
	for _, o := range []struct {
		args []string
		add  func(string) error
	}{
		{req.See, func(a string) error { return rs.AddPolicy(a, policySee) }},
		{req.Talk, func(a string) error { return rs.AddPolicy(a, policyTalk) }},
		{req.Own, func(a string) error { return rs.AddPolicy(a, policyOwn) }},
		{req.Call, func(a string) error { return rs.AddRule(a, filterCall) }},
		{req.Broadcast, func(a string) error { return rs.AddRule(a, filterBroadcast) }},
	} {
		for _, a := range o.args {
			if err := o.add(a); err != nil {
				return nil, err
			}
			if rs.size() > maxSetEntries {
				return nil, fmt.Errorf("%d rules in a set at most", maxSetEntries)
			}
		}
	}
	if rs.size() == 0 {
		return nil, errors.New("A rule set without rules")
	}
	if rs.byName[busName] != nil {
		return nil, fmt.Errorf("%s: the bus itself takes no live rules", busName)
	}
	set := dbuspolicy.Set{See: req.See, Talk: req.Talk, Own: req.Own, Call: byName(req.Call), Broadcast: byName(req.Broadcast)}
	if err := dbuspolicy.Check(bus, appID, set); err != nil {
		return nil, err
	}
	return rs, nil
}

// byName turns NAME=RULE arguments, parsed already, into rules by name
func byName(args []string) map[string][]string {
	out := map[string][]string{}
	for _, a := range args {
		name, rule, _ := strings.Cut(a, "=")
		out[name] = append(out[name], rule)
	}
	return out
}
