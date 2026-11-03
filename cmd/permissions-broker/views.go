package main

import (
	"errors"
	"os/exec"
	"slices"
	"sort"
)

func (b *broker) listCapabilities() []capabilityInfo {
	ids := make([]string, 0, len(b.caps))
	for id := range b.caps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	infos := make([]capabilityInfo, len(ids))
	for i, id := range ids {
		c := b.caps[id]
		infos[i] = capabilityInfo{ID: id, Type: c.Type, Description: c.Description, Params: c.Params}
		c.kind().info(c, &infos[i])
		if inst, err := c.listInstances(); err != nil {
			infos[i].Error = err.Error()
		} else {
			infos[i].Instances = inst
		}
	}
	return infos
}

func (b *broker) liveGrants() []*grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	var gs []*grant
	for _, g := range b.grants {
		gs = append(gs, g)
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].Granted.Before(gs[j].Granted) })
	return gs
}

// view is a copy of g for a response, taken under b.mu: the response is encoded outside it, while the grant's
// holders may change
func (b *broker) view(g *grant) *grant {
	if g == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return snapshot(g)
}

func snapshot(g *grant) *grant {
	c := *g
	c.conns = nil
	c.Holders = slices.Clone(g.Holders)
	return &c
}

// grantViews is liveGrants as copies, for responses
func (b *broker) grantViews() []*grant {
	gs := b.liveGrants()
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, g := range gs {
		gs[i] = snapshot(g)
	}
	return gs
}

// openWindow opens the Permissions window on the host, as a unit of its own
func (b *broker) openWindow() error {
	if len(b.cfg.Window) == 0 {
		return errors.New("No window configured")
	}
	args := append([]string{"--user", "--collect", "--quiet", "--"}, b.cfg.Window...)
	return exec.Command(systemdRun, args...).Run()
}
