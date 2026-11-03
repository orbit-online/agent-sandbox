package main

import (
	"bufio"
	"encoding/json"
	"maps"
	"net"
	"slices"
	"sync"

	"pgregory.net/rapid"
)

// The state machine's D-Bus proxy: a stand-in for its control socket that keeps each connection's rule sets, as the
// proxy does, and drops them when the connection closes. The D-Bus capability capBus is requested like the others and
// is a standing grant; after every step the sets live there are the reference's D-Bus grants (P4)

const capBus = "bus"

type proxyStandIn struct {
	ln   net.Listener
	mu   sync.Mutex
	live map[string]net.Conn // set id: the connection that added it
}

func startProxyStandIn(t *rapid.T, path string) *proxyStandIn {
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	p := &proxyStandIn{ln: ln, live: map[string]net.Conn{}}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn)
		}
	}()
	return p
}

func (p *proxyStandIn) serve(conn net.Conn) {
	defer func() {
		conn.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for id, c := range p.live {
			if c == conn {
				delete(p.live, id)
			}
		}
	}()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var s dbusSet
		_ = json.Unmarshal(line, &s)
		res := `{"ok":true}`
		p.mu.Lock()
		switch {
		case s.Op == "add" && p.live[s.ID] == nil:
			p.live[s.ID] = conn
		case s.Op == "remove" && p.live[s.ID] == conn:
			delete(p.live, s.ID)
		default:
			res = `{"error":"no"}`
		}
		p.mu.Unlock()
		if _, err := conn.Write([]byte(res + "\n")); err != nil {
			return
		}
	}
}

func (p *proxyStandIn) ids() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Sorted(maps.Keys(p.live))
}

// checkProxy: the sets the proxy holds are the live D-Bus grants. A daemon's connection closing drops its sets on the
// proxy's own time, so it's waited for
func (mc *machine) checkProxy(t *rapid.T) {
	var want []string
	for id, g := range mc.m.grants {
		if g.cap == capBus {
			want = append(want, id)
		}
	}
	slices.Sort(want)
	mc.waitFor(t, "the proxy's rule sets to be the D-Bus grants", func() bool { return slices.Equal(mc.w.proxy.ids(), want) })
}
