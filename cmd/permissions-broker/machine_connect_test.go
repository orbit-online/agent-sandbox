package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"pgregory.net/rapid"
)

// The state machine's connections to host sockets (machine_test.go): at the console's stable address, spliced to the
// instance's echo server while a grant covers it, closed at once otherwise, and closed when the grant ends or the
// instance goes away

// A connection the sandbox keeps open, spliced under a grant to an instance's console
type openConn struct {
	conn  *net.UnixConn
	in    *bufio.Reader
	grant string
	name  string
}

// At most this many connections stay open: each is checked after every step
const maxOpen = 3

// Connect: something in the sandbox connects to an instance's console. With a live grant and the instance there, what
// it sends comes back from the host; otherwise the connection is closed at once, or there's nothing to connect to
// where the broker doesn't listen
func (mc *machine) Connect(t *rapid.T) {
	n := rapid.SampledFrom([]string{"a", "b", "c"}).Draw(t, "instance")
	addr := filepath.Join(mc.w.cfg.GrantDir, socketsDir, capConsole, n)
	conn, err := dialPath(addr, settle)
	if !mc.m.listening[n] {
		if err == nil {
			conn.Close()
			mc.fatalf(t, "Connected to the console of %s, where the broker doesn't listen", n)
		}
		return
	}
	if err != nil {
		mc.fatalf(t, "Connect to the console of %s: %v", n, err)
	}
	g := mc.m.matching(capConsole, params(map[string]any{"name": n}))
	c := &openConn{conn: conn, in: bufio.NewReader(conn), name: n}
	if g == nil || !mc.m.listed[n] {
		if err := c.closedAtOnce(); err != nil {
			mc.fatalf(t, "Console of %s without a grant (%v) or with its instance gone (%v): %v", n, g != nil,
				!mc.m.listed[n], err)
		}
		return
	}
	c.grant = g.id
	if err := c.echoes(fmt.Sprintf("ping %d", mc.tags)); err != nil {
		mc.fatalf(t, "Console of %s under %s: %v", n, g.id, err)
	}
	if len(mc.conns) >= maxOpen {
		conn.Close()
		return
	}
	mc.conns = append(mc.conns, c)
}

// echoes sends a line and reads it back from the host
func (c *openConn) echoes(line string) error {
	_ = c.conn.SetDeadline(time.Now().Add(settle))
	defer c.conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(c.conn, line+"\n"); err != nil {
		return err
	}
	got, err := c.in.ReadString('\n')
	if err != nil || got != line+"\n" {
		return fmt.Errorf("sent %q, got %q, %v", line, got, err)
	}
	return nil
}

// closedAtOnce reads the end of the connection, which comes without anything before it
func (c *openConn) closedAtOnce() error {
	defer c.conn.Close()
	_ = c.conn.SetDeadline(time.Now().Add(settle))
	_, _ = io.WriteString(c.conn, "ping\n")
	// A connection closed with what was sent unread is reset
	if b, err := c.in.ReadByte(); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return fmt.Errorf("read %q, %v, not the connection's end", b, err)
	}
	return nil
}

// hungUp checks that the open connections gone picks are closed, and forgets them
func (mc *machine) hungUp(t *rapid.T, gone func(*openConn) bool) {
	for _, c := range mc.conns {
		if !gone(c) {
			continue
		}
		if err := c.closedAtOnce(); err != nil {
			mc.fatalf(t, "Console of %s under %s still open: %v", c.name, c.grant, err)
		}
	}
	mc.conns = slices.DeleteFunc(mc.conns, gone)
}

// checkConns: the connections of grants that ended are closed (a revoke closes them, P4), the others still reach
// the host
func (mc *machine) checkConns(t *rapid.T) {
	mc.hungUp(t, func(c *openConn) bool { return mc.m.grants[c.grant] == nil })
	for _, c := range mc.conns {
		if err := c.echoes("still"); err != nil {
			mc.fatalf(t, "Console of %s under %s: %v", c.name, c.grant, err)
		}
	}
}
