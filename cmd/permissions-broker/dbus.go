package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/dbusgrant"
)

// D-Bus capabilities: internal/dbusgrant has their declarations, scope and the proxies' control sockets

// loadDBus makes the config's D-Bus capabilities, each under its own name, for the sandbox of app ID appID
func loadDBus(cfgs []dbusgrant.Config, caps map[string]*capability, appID string) error {
	for i := range cfgs {
		dc := cfgs[i].For(appID)
		c := &capability{Name: dc.Name, Type: "dbus", Description: dc.Description, DBus: dc}
		if err := c.check(); err != nil {
			return fmt.Errorf("D-Bus capability %s: %w", dc.Name, err)
		}
		if _, dup := caps[c.id()]; dup {
			return fmt.Errorf("Capability %s declared twice", c.id())
		}
		caps[c.id()] = c
	}
	return nil
}

// checkDBus checks a D-Bus capability: a name, a description, no bounding arguments, and its rule set
func (c *capability) checkDBus() error {
	switch {
	case !commandName.MatchString(c.Name):
		return fmt.Errorf("name %q: letters, digits and -", c.Name)
	case c.Description == "":
		return errors.New("no description: the consent names it")
	case len(c.Params) > 0:
		return errors.New("no bounding arguments: a D-Bus capability is granted whole")
	}
	return c.DBus.Check()
}

// proxyFor is the connection to bus's proxy
func (b *broker) proxyFor(bus string) (*dbusgrant.Proxy, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	path := b.cfg.DBusControl[bus]
	if path == "" {
		return nil, fmt.Errorf("No D-Bus proxy for the %s bus", bus)
	}
	if b.proxies == nil {
		b.proxies = map[string]*dbusgrant.Proxy{}
	}
	if b.proxies[bus] == nil {
		b.proxies[bus] = dbusgrant.NewProxy(path)
	}
	return b.proxies[bus], nil
}

// dbusAdd adds g's rule set to its bus's proxy
func (b *broker) dbusAdd(g *grant) error {
	p, err := b.proxyFor(g.cap.DBus.Bus)
	if err != nil {
		return err
	}
	lost, err := p.Add(g.ID, g.cap.DBus)
	if lost {
		go b.dbusLost(g.cap.DBus.Bus)
	}
	return err
}

// dbusRemove removes g's rule set from its bus's proxy
func (b *broker) dbusRemove(g *grant) {
	p, err := b.proxyFor(g.cap.DBus.Bus)
	if err != nil {
		return
	}
	lost, err := p.Remove(g.ID)
	if err != nil {
		slog.Warn("Remove the D-Bus rules", "grant", g.ID, "err", err)
	}
	if lost {
		go b.dbusLost(g.cap.DBus.Bus)
	}
}

// dbusLost ends the grants on bus: its proxy dropped their rules with the broker's connection
func (b *broker) dbusLost(bus string) {
	for _, g := range b.liveGrants() {
		if g.cap.Type == "dbus" && g.cap.DBus.Bus == bus {
			g.end("the D-Bus proxy's connection broke")
		}
	}
}

// closeProxies closes the connections to the proxies, which drop the broker's rule sets
func (b *broker) closeProxies() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.proxies {
		p.Close()
	}
}
