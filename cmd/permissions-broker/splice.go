package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostsock"
)

// Connections to a host socket's address: under a live grant, spliced to the host socket, bytes copied both ways and
// nothing parsed; without one, closed at once. No file descriptors pass. A grant's end closes its connections

// acceptLoop accepts on ln until it's closed, at most maxConns connections at a time: each socket has its own budget,
// so the sandbox filling one leaves the others. Accept errors (out of fds) are waited out, not fatal
func acceptLoop(ln *net.UnixListener, handle func(*net.UnixConn)) {
	slots := make(chan struct{}, maxConns)
	backoff := 10 * time.Millisecond
	for {
		conn, err := ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("Accept", "err", err)
			time.Sleep(backoff)
			backoff = min(2*backoff, time.Second)
			continue
		}
		backoff = 10 * time.Millisecond
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			handle(conn)
		}()
	}
}

// How long the broker waits for a host socket to accept
var dialTimeout = 10 * time.Second

// A spliced connection: the sandbox's end and, once connected, the host's
type spliced struct {
	mu       sync.Mutex
	down, up *net.UnixConn
	closed   bool
}

// attach adds the host's end, unless the connection was closed meanwhile
func (s *spliced) attach(up *net.UnixConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.up = up
	return true
}

func (s *spliced) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.down.Close()
	if s.up != nil {
		s.up.Close()
	}
}

// splice serves a connection to the address of c's host socket with params (the instance): spliced to host while a
// live grant covers it
func (b *broker) splice(conn *net.UnixConn, c *capability, params json.RawMessage, host string) {
	s := &spliced{down: conn}
	g := b.connectUnder(c, params, s)
	if g == nil {
		conn.Close()
		return
	}
	defer b.dropConn(g, s)
	defer s.close()
	beforeDial()
	up, err := hostsock.Dial(host, dialTimeout)
	if err != nil {
		slog.Warn("Connect to a host socket", "capability", c.id(), "grant", g.ID, "err", err)
		return
	}
	if !s.attach(up) {
		up.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, conn)
		_ = up.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, up)
		_ = conn.CloseWrite()
		done <- struct{}{}
	}()
	<-done
	<-done
}

// connectUnder records s as a connection of the live grant covering c with params, and returns that grant: nil
// without one
func (b *broker) connectUnder(c *capability, params json.RawMessage, s *spliced) *grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, g := range b.grants {
		// b.grants holds no grant that's ending: end deletes it under b.mu before it closes the connections
		if g.cap == c && string(g.Params) == string(params) {
			if g.conns == nil {
				g.conns = map[*spliced]bool{}
			}
			g.conns[s] = true
			return g
		}
	}
	return nil
}

func (b *broker) dropConn(g *grant, s *spliced) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(g.conns, s)
}

// closeConns closes the connections spliced under g, which ends: under b.mu with over set, so none is added after
func (b *broker) closeConns(g *grant) {
	b.mu.Lock()
	conns := g.conns
	g.conns = nil
	b.mu.Unlock()
	for s := range conns {
		s.close()
	}
}
