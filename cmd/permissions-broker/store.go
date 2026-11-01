package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// isAlways: exact parameters only, so read-only never covers read-write and a folder never its sub- or parent folder
func (b *broker) isAlways(c *capability, params json.RawMessage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.store.Always {
		if a.Capability == c.id() && string(a.Params) == string(params) {
			return true
		}
	}
	return false
}

// replay grants the stored always grants of a type: service at launch, attach once the grant directory is shared. A
// command runs on request without asking
func (b *broker) replay(typ string) {
	b.mu.Lock()
	always := append([]alwaysGrant(nil), b.store.Always...)
	b.mu.Unlock()
	for _, a := range always {
		c, ok := b.caps[a.Capability]
		if !ok || c.Type != typ {
			continue
		}
		params, err := c.validate(a.Params)
		if err != nil {
			slog.Warn("Replay", "capability", a.Capability, "err", err)
			continue
		}
		summary := c.describe(params)
		if typ == "attach" {
			src, err := b.resolveAttach(c, params)
			if err != nil {
				slog.Warn("Replay", "capability", a.Capability, "err", err)
				continue
			}
			summary = describeAttach(summary, src)
		} else if err := c.inList(context.Background(), params); err != nil {
			// As for a request: no instance list doesn't print (a VM no longer there)
			slog.Warn("Replay", "capability", a.Capability, "err", err)
			continue
		}
		// Once per parameters: under c.covered, as requests look for a live grant, so a replay racing a request or
		// another replay doesn't make a second grant (a second mount nothing ends)
		c.covered.Lock()
		if b.matching(c, params) == nil {
			if _, err := b.grant(c, params, summary, "always", nil); err != nil {
				slog.Warn("Replay", "capability", a.Capability, "err", err)
			}
		}
		c.covered.Unlock()
	}
}

func (b *broker) addAlways(c *capability, params json.RawMessage) {
	b.mu.Lock()
	b.store.Always = append(b.store.Always, alwaysGrant{Capability: c.id(), Params: params, Granted: b.now()})
	b.mu.Unlock()
	b.save()
}

// forget removes an always grant and ends its live grants
func (b *broker) forget(capID string, params json.RawMessage) error {
	c, ok := b.caps[capID]
	if !ok {
		return fmt.Errorf("No capability %q", capID)
	}
	params, err := c.validate(params)
	if err != nil {
		return err
	}
	b.removeAlways(capID, params)
	for _, g := range b.liveGrants("") {
		if g.cap == c && string(g.Params) == string(params) && g.Lease == "always" {
			g.end("forgotten by the user")
		}
	}
	return nil
}

// removeAlways removes an always grant from the store
func (b *broker) removeAlways(capID string, params json.RawMessage) {
	b.mu.Lock()
	kept := b.store.Always[:0]
	for _, a := range b.store.Always {
		if a.Capability != capID || string(a.Params) != string(params) {
			kept = append(kept, a)
		}
	}
	b.store.Always = kept
	b.mu.Unlock()
	b.save()
}

func (b *broker) logDecision(summary, reason, decision string) {
	b.mu.Lock()
	b.store.Log = append(b.store.Log, logEntry{Time: b.now(), Summary: summary, Reason: reason, Decision: decision})
	if n := len(b.store.Log); n > maxLog {
		b.store.Log = b.store.Log[n-maxLog:]
	}
	b.mu.Unlock()
	b.save()
}

// save writes the store atomically, one save at a time so an older snapshot can't land last
func (b *broker) save() {
	b.saving.Lock()
	defer b.saving.Unlock()
	b.mu.Lock()
	data, _ := json.MarshalIndent(b.store, "", "  ")
	b.mu.Unlock()
	tmp := b.cfg.Store + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err == nil {
		_, err = f.Write(data)
		err = errors.Join(err, f.Sync(), f.Close())
	}
	if err == nil {
		err = os.Rename(tmp, b.cfg.Store)
	}
	if err != nil {
		slog.Warn("Save the grant store", "err", err)
	}
}

// removeOwnLocks removes the exclusive locks a previous daemon of this launcher left
func (b *broker) removeOwnLocks() { removeLocks(b.cfg.Launcher) }
