package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostsock"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/schema"
)

// Host sockets (docs/permissions.md): a socket on the host the module declares, reachable at a stable address in the
// grant directory, sockets/<capability> or sockets/<capability>/<instance> with an instances glob. The broker listens
// there from its start, or from when the instance appears; splice.go serves the connections

// Where the host sockets' addresses are, in the grant directory
const socketsDir = "sockets"

// A host socket capability, as the config declares it: a socket, or an instances glob on its one bounding argument
type socketConfig struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Path        string                     `json:"path,omitempty"`
	Bounding    map[string]json.RawMessage `json:"bounding,omitempty"`
}

// loadSockets makes the config's host socket capabilities, each under its own name
func loadSockets(cfgs []socketConfig, caps map[string]*capability) error {
	for _, sc := range cfgs {
		c := &capability{Name: sc.Name, Type: "socket", Description: sc.Description, Params: sc.Bounding, Path: sc.Path}
		if err := c.check(); err != nil {
			return fmt.Errorf("Host socket %s: %w", sc.Name, err)
		}
		if _, dup := caps[c.id()]; dup {
			return fmt.Errorf("Capability %s declared twice", c.id())
		}
		caps[c.id()] = c
	}
	return nil
}

// checkSocket checks a host socket capability: a name that makes a file name, and either a path or one bounding
// argument with an instances glob, which the broker doesn't refuse
func (c *capability) checkSocket() error {
	if !commandName.MatchString(c.Name) {
		return fmt.Errorf("name %q: letters, digits and -", c.Name)
	}
	if c.Description == "" {
		return errors.New("no description: the consent names it")
	}
	if err := c.checkBounding(); err != nil {
		return err
	}
	if c.glob == "" && (c.Path == "" || len(c.schemas) > 0) || c.glob != "" && (c.Path != "" || len(c.schemas) != 1) {
		return errors.New("a path, or no path and one bounding argument with instances")
	}
	for _, p := range []string{c.Path, c.glob} {
		if v := hostsock.UnsetVariable(p); v != "" {
			return fmt.Errorf("%s: $%s isn't set", p, v)
		}
	}
	if len(c.Name) > hostsock.MaxAddrName {
		return fmt.Errorf("name %q: %d characters at most, the length an address may have", c.Name, hostsock.MaxAddrName)
	}
	if c.Path != "" {
		return hostsock.Refused(expandPath(c.Path))
	}
	// An instance names its address: a value too long for one isn't an instance
	if s := c.schemas[c.globArg]; s.MaxLength == nil || *s.MaxLength > hostsock.MaxAddrName {
		n := hostsock.MaxAddrName
		if s.MaxLength != nil && *s.MaxLength < n {
			n = *s.MaxLength
		}
		s.MaxLength = &n
	}
	return hostsock.RefusedGlob(expandPath(c.glob))
}

// Tests' hooks: after syncSockets looked for instances, before splice connects to the host
var (
	globbed    = func() {}
	beforeDial = func() {}
)

// A listener at a host socket's address, and the host socket it leads to
type hostListener struct {
	ln   *net.UnixListener
	host string
}

// socketAddr is where a host socket of c is in the grant directory, relative to it: sockets/<name>, or
// sockets/<name>/<instance>
func socketAddr(c *capability, params json.RawMessage) string {
	if c.globArg == "" {
		return filepath.Join(socketsDir, c.Name)
	}
	m, _ := schema.DecodeObject(params)
	v, _ := m[c.globArg].(string)
	return filepath.Join(socketsDir, c.Name, v)
}

// syncSockets listens at the address of each of c's host sockets there is, and stops listening at those of instances
// gone
func (b *broker) syncSockets(c *capability) {
	// The whole sync under socketsMu: one that looked for instances before a grant's did mustn't close the listener
	// the grant's opened
	b.socketsMu.Lock()
	defer b.socketsMu.Unlock()
	want := map[string]string{}
	if c.glob == "" {
		want[socketAddr(c, nil)] = expandPath(c.Path)
	} else {
		found, err := c.globMatches()
		globbed()
		if err != nil {
			slog.Warn("Host socket instances", "capability", c.id(), "err", err)
		}
		for v, host := range found {
			params, _ := json.Marshal(map[string]string{c.globArg: v})
			want[socketAddr(c, params)] = host
		}
	}
	if b.listeners == nil {
		b.listeners = map[string]*hostListener{}
	}
	mine := func(addr string) bool {
		return addr == socketAddr(c, nil) || strings.HasPrefix(addr, socketAddr(c, nil)+"/")
	}
	for addr, l := range b.listeners {
		if mine(addr) && want[addr] != l.host {
			l.ln.Close()
			_ = os.Remove(filepath.Join(b.cfg.GrantDir, addr))
			delete(b.listeners, addr)
		}
	}
	for addr, host := range want {
		if b.listeners[addr] != nil {
			continue
		}
		ln, err := hostsock.Listen(b.cfg.GrantDir, addr)
		if err != nil {
			slog.Warn("Listen for a host socket", "capability", c.id(), "at", addr, "err", err)
			continue
		}
		b.listeners[addr] = &hostListener{ln: ln, host: host}
		params := json.RawMessage(`{}`)
		if c.globArg != "" {
			params, _ = json.Marshal(map[string]string{c.globArg: filepath.Base(addr)})
		}
		go acceptLoop(ln, func(conn *net.UnixConn) { b.splice(conn, c, params, host) })
	}
}

// listening reports whether the broker listens at addr
func (b *broker) listening(addr string) bool {
	b.socketsMu.Lock()
	defer b.socketsMu.Unlock()
	return b.listeners[addr] != nil
}

// syncSocketsEvery looks for host sockets' instances every instanceEvery, for as long as the daemon runs
func (b *broker) syncSocketsEvery() {
	for {
		<-b.clock.after(instanceEvery)
		for _, c := range b.caps {
			if c.Type == "socket" && c.glob != "" {
				b.syncSockets(c)
			}
		}
	}
}

// closeSockets stops listening at the host sockets' addresses
func (b *broker) closeSockets() {
	b.socketsMu.Lock()
	defer b.socketsMu.Unlock()
	for addr, l := range b.listeners {
		l.ln.Close()
		delete(b.listeners, addr)
	}
}

// socketKind is the kind of host socket capabilities: the broker listens at their addresses from its start, and a
// grant lets connections there through
type socketKind struct{ baseKind }

func (socketKind) check(c *capability) error { return c.checkSocket() }

func (socketKind) start(b *broker, c *capability) { b.syncSockets(c) }

func (socketKind) live(b *broker, g *grant) error {
	b.syncSockets(g.cap)
	addr := socketAddr(g.cap, g.Params)
	if !b.listening(addr) {
		return fmt.Errorf("Can't listen at %s for %s", addr, g.cap.id())
	}
	g.Socket = filepath.Join(b.cfg.SandboxGrantDir, addr)
	return nil
}
