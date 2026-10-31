package main

import (
	"context"
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
		infos[i] = capabilityInfo{ID: id, Type: c.Type, Description: c.Description, Params: c.Params,
			Tools: c.Type == "A" && c.Tools}
		if inst, err := c.listInstances(context.Background()); err != nil {
			infos[i].Error = err.Error()
		} else {
			infos[i].Instances = inst
		}
	}
	return infos
}

func (b *broker) liveGrants(session string) []*grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	var gs []*grant
	for _, g := range b.grants {
		if session == "" || slices.Contains(g.Sessions, session) {
			gs = append(gs, g)
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].Granted.Before(gs[j].Granted) })
	return gs
}

// view is a copy of g for a response, taken under b.mu: the response is encoded outside it, while the grant's
// sessions may change
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
	c.Sessions = slices.Clone(g.Sessions)
	c.Holders = slices.Clone(g.Holders)
	return &c
}

// grantViews is liveGrants as copies, for responses
func (b *broker) grantViews(session string) []*grant {
	gs := b.liveGrants(session)
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, g := range gs {
		gs[i] = snapshot(g)
	}
	return gs
}
