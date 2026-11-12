package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Where a program sits on each uplink: ahead of einat (and everything else) or behind it
type hook struct {
	prog   string
	attach ebpf.AttachType
	head   bool
}

var hooks = []hook{
	{"pre", ebpf.AttachTCXIngress, true},
	{"post", ebpf.AttachTCXIngress, false},
	{"egress", ebpf.AttachTCXEgress, false},
}

// loader holds the programs and, per uplink, the ifindex they're attached on and their links, pinned in dir
// (pinName) so they stay attached while sandbox-uplink isn't running (failing closed)
type loader struct {
	dir     string
	progs   map[string]*ebpf.Program
	ifindex map[string]int
	links   map[string]link.Link
	sbx     *sandboxes
	mdns    *mdnsGroups
}

// load loads the programs with the sandbox blocks, reusing the pinned registration map, which the per-launcher helper
// writes as group sandbox-uplink
func load(object, dir string, v4, v6 netip.Prefix) (*loader, error) {
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return nil, fmt.Errorf("Read %s: %w", object, err)
	}
	mask := net.CIDRMask(v4.Bits(), 32)
	for name, v := range map[string]any{
		"v4_net":   v4.Masked().Addr().As4(),
		"v4_mask":  [4]byte(mask),
		"v6_block": [6]byte(v6.Addr().AsSlice()[:6]),
	} {
		if err := spec.Variables[name].Set(v); err != nil {
			return nil, fmt.Errorf("Set %s: %w", name, err)
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: dir}})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			slog.Error("Verifier", "log", fmt.Sprintf("%+v", ve))
		}
		return nil, fmt.Errorf("Load %s: %w", object, err)
	}
	// Pinned 0600
	for _, m := range []string{"sandboxes", "mdns"} {
		if err := os.Chmod(filepath.Join(dir, m), 0o660); err != nil {
			return nil, fmt.Errorf("Open the %s map to its group: %w", m, err)
		}
	}
	sbx, err := openSandboxes(dir, coll.Maps["sandboxes"], coll.Maps["mdns"])
	if err != nil {
		return nil, err
	}
	groups, err := openMdnsGroups()
	if err != nil {
		return nil, err
	}
	return &loader{dir, coll.Programs, map[string]int{}, map[string]link.Link{}, sbx, groups}, nil
}

// pinName is where the link of a program on an uplink is pinned: <program>-<uplink>, its dots as colons, which no device
// name holds. bpffs refuses names with a dot (EPERM, bpf_lookup)
func pinName(uplink, prog string) string {
	return prog + "-" + strings.ReplaceAll(uplink, ".", ":")
}

// pinOf parses a pinName
func pinOf(name string) (uplink, prog string, ok bool) {
	prog, uplink, ok = strings.Cut(name, "-")
	return strings.ReplaceAll(uplink, ":", "."), prog, ok
}

// unpinOthers detaches what an earlier run attached on devices that are no longer uplinks
func (l *loader) unpinOthers(uplinks []string) error {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return fmt.Errorf("List %s: %w", l.dir, err)
	}
	for _, e := range entries {
		dev, prog, ok := pinOf(e.Name())
		if !ok || l.progs[prog] == nil || slices.Contains(uplinks, dev) {
			continue
		}
		if err := unpin(filepath.Join(l.dir, e.Name())); err != nil {
			return err
		}
		slog.Info("Detached", "device", dev, "program", prog)
	}
	return nil
}

func unpin(path string) error {
	old, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return fmt.Errorf("Load %s: %w", path, err)
	}
	defer old.Close()
	if err := old.Unpin(); err != nil {
		return fmt.Errorf("Unpin %s: %w", path, err)
	}
	return nil
}

// sync attaches the programs on the current device of the uplink and puts them back in order around einat, which takes
// the head of tcx ingress whenever it (re)attaches: after a restart and on link up. Until pre is ahead again it drops
// the replies einat rewrote to a sandbox address, so a wrong order fails closed (network.als N5)
func (l *loader) sync(uplink string) error {
	iface, err := net.InterfaceByName(uplink)
	if err != nil {
		return nil // Not there (yet): einat follows it, and so does the next sync
	}
	if iface.Index != l.ifindex[uplink] {
		for _, h := range hooks {
			if err := l.attach(uplink, iface.Index, h); err != nil {
				return err
			}
		}
		l.ifindex[uplink] = iface.Index
		l.mdns.join(uplink, iface.Index)
		slog.Info("Attached", "uplink", uplink, "ifindex", iface.Index)
	}
	for _, h := range hooks {
		ok, err := l.inPlace(uplink, iface.Index, h)
		if err != nil {
			return err
		}
		if ok {
			continue
		}
		start := time.Now()
		if err := l.reattach(uplink, iface.Index, h); err != nil {
			return err
		}
		slog.Info("Reordered", "uplink", uplink, "program", h.prog, "took", time.Since(start))
	}
	return nil
}

// attach takes over the pinned link when it is on this device, with the program just loaded, or attaches a new one
func (l *loader) attach(uplink string, ifindex int, h hook) error {
	key := pinName(uplink, h.prog)
	path := filepath.Join(l.dir, key)
	if old := l.links[key]; old != nil {
		old.Close()
		delete(l.links, key)
	}
	pinned, err := link.LoadPinnedLink(path, nil)
	if err == nil {
		info, err := pinned.Info()
		if err == nil && info.TCX() != nil && int(info.TCX().Ifindex) == ifindex {
			if err := pinned.Update(l.progs[h.prog]); err != nil {
				pinned.Close()
				return fmt.Errorf("Update %s: %w", path, err)
			}
			l.links[key] = pinned
			return nil
		}
		// A device that went away
		pinned.Unpin()
		pinned.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Load %s: %w", path, err)
	}
	return l.attachNew(key, path, ifindex, h)
}

func (l *loader) attachNew(key, path string, ifindex int, h hook) error {
	anchor := link.Tail()
	if h.head {
		anchor = link.Head()
	}
	ln, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: l.progs[h.prog], Attach: h.attach, Anchor: anchor})
	if err != nil {
		return fmt.Errorf("Attach %s: %w", key, err)
	}
	if err := ln.Pin(path); err != nil {
		ln.Close()
		return fmt.Errorf("Pin %s: %w", path, err)
	}
	l.links[key] = ln
	return nil
}

// inPlace says whether the link of the program is first (head) or last on its hook
func (l *loader) inPlace(uplink string, ifindex int, h hook) (bool, error) {
	info, err := l.links[pinName(uplink, h.prog)].Info()
	if err != nil {
		return false, fmt.Errorf("Read the %s link on %s: %w", h.prog, uplink, err)
	}
	q, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: h.attach})
	if err != nil {
		return false, fmt.Errorf("Query %s on %s: %w", h.attach, uplink, err)
	}
	if len(q.Programs) == 0 {
		return false, nil
	}
	end := q.Programs[len(q.Programs)-1]
	if h.head {
		end = q.Programs[0]
	}
	id, _ := end.LinkID()
	return id == info.ID, nil
}

// reattach moves a program back to its end of the hook. tcx refuses a program twice on one hook, so the old link
// goes first; meanwhile post drops what lacks the mark from pre
func (l *loader) reattach(uplink string, ifindex int, h hook) error {
	key := pinName(uplink, h.prog)
	path := filepath.Join(l.dir, key)
	if err := l.links[key].Unpin(); err != nil {
		return fmt.Errorf("Unpin %s: %w", path, err)
	}
	l.links[key].Close()
	delete(l.links, key)
	return l.attachNew(key, path, ifindex, h)
}

// keep syncs every uplink and tends the sandboxes until ctx ends, every interval; ready runs after the first round
func (l *loader) keep(ctx context.Context, uplinks []string, interval time.Duration, ready func()) {
	for {
		for _, u := range uplinks {
			if err := l.sync(u); err != nil {
				slog.Error("Sync", "uplink", u, "err", err)
			}
		}
		l.sbx.tend(uplinks)
		if ready != nil {
			ready()
			ready = nil
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
