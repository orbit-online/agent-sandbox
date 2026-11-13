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

// The programs on each uplink: pre at the head of tcx ingress, ahead of einat and everything else; post and egress
// right after the einat link of tcx ingress and egress, so ahead of Cilium, which attaches at the tail and ends the
// chain (TC_ACT_OK)
type hook struct {
	prog   string
	attach ebpf.AttachType
}

var hooks = []hook{
	{"pre", ebpf.AttachTCXIngress},
	{"post", ebpf.AttachTCXIngress},
	{"egress", ebpf.AttachTCXEgress},
}

// loader holds the programs, each loaded twice (tcx refuses a program twice on one hook, and place attaches the other
// instance before it detaches the one in place), and per uplink the ifindex they're attached on and their links, pinned
// in dir (pinName) so they stay attached while sandbox-uplink isn't running (failing closed), per link the instance in
// it, and per link of post and egress the einat program it follows (einatProg)
type loader struct {
	dir     string
	progs   map[string][2]*ebpf.Program
	ifindex map[string]int
	ids     map[string][2]ebpf.ProgramID
	links   map[string]link.Link
	inst    map[string]int
	einat   map[string]ebpf.ProgramID
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
	var colls [2]*ebpf.Collection
	for i := range colls {
		// The second instance shares the pinned maps of the first
		colls[i], err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: dir}})
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				slog.Error("Verifier", "log", fmt.Sprintf("%+v", ve))
			}
			return nil, fmt.Errorf("Load %s: %w", object, err)
		}
	}
	coll := colls[0]
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
	progs, ids := map[string][2]*ebpf.Program{}, map[string][2]ebpf.ProgramID{}
	for name := range coll.Programs {
		var ps [2]*ebpf.Program
		var is [2]ebpf.ProgramID
		for i, c := range colls {
			ps[i] = c.Programs[name]
			info, err := ps[i].Info()
			if err != nil {
				return nil, fmt.Errorf("Read program %s: %w", name, err)
			}
			is[i], _ = info.ID()
		}
		progs[name], ids[name] = ps, is
	}
	return &loader{dir, progs, map[string]int{}, ids, map[string]link.Link{}, map[string]int{}, map[string]ebpf.ProgramID{}, sbx, groups}, nil
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
		if _, known := l.progs[prog]; !ok || !known || slices.Contains(uplinks, dev) {
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
// the head of tcx ingress and egress whenever it (re)attaches: after a restart and on link up. Until pre is ahead again
// it drops the replies einat rewrote to a sandbox address, so a wrong order fails closed (network.als N5)
func (l *loader) sync(uplink string) error {
	iface, err := net.InterfaceByName(uplink)
	if err != nil {
		return nil // Not there (yet): einat follows it, and so does the next sync
	}
	if iface.Index != l.ifindex[uplink] {
		for _, h := range hooks {
			if err := l.adopt(uplink, iface.Index, h); err != nil {
				return err
			}
			delete(l.einat, pinName(uplink, h.prog))
		}
	}
	for _, h := range hooks {
		if err := l.place(uplink, iface.Index, h); err != nil {
			return err
		}
	}
	if iface.Index != l.ifindex[uplink] {
		l.ifindex[uplink] = iface.Index
		l.mdns.join(uplink, iface.Index)
		slog.Info("Attached", "uplink", uplink, "ifindex", iface.Index)
	}
	return nil
}

// adopt takes over the pinned link when it is on this device, with the program just loaded; place attaches the others
func (l *loader) adopt(uplink string, ifindex int, h hook) error {
	key := pinName(uplink, h.prog)
	path := filepath.Join(l.dir, key)
	if old := l.links[key]; old != nil {
		old.Close()
		delete(l.links, key)
	}
	pinned, err := link.LoadPinnedLink(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("Load %s: %w", path, err)
	}
	info, err := pinned.Info()
	if err == nil && info.TCX() != nil && int(info.TCX().Ifindex) == ifindex {
		if err := pinned.Update(l.progs[h.prog][0]); err != nil {
			pinned.Close()
			return fmt.Errorf("Update %s: %w", path, err)
		}
		l.links[key] = pinned
		l.inst[key] = 0
		return nil
	}
	// A device that went away
	pinned.Unpin()
	pinned.Close()
	return nil
}

// place attaches the program where it belongs on its hook, or moves it back there: pre at the head, post and egress
// right after einat. A move attaches the other instance in place before it detaches the old link, so the hook never
// lacks the program (network.als MakeBeforeBreak). Without einat on the hook post and egress stay where they are, or
// go right after pre and at the head: einat comes ahead of them when it attaches
func (l *loader) place(uplink string, ifindex int, h hook) error {
	key := pinName(uplink, h.prog)
	q, err := link.QueryPrograms(link.QueryOptions{Target: ifindex, Attach: h.attach})
	if err != nil {
		return fmt.Errorf("Query %s on %s: %w", h.attach, uplink, err)
	}
	ids := make([]ebpf.ProgramID, 0, len(q.Programs))
	for _, p := range q.Programs {
		ids = append(ids, p.ID)
	}
	ours := map[ebpf.ProgramID]bool{}
	for _, o := range hooks {
		if l.links[pinName(uplink, o.prog)] != nil && o.attach == h.attach {
			ours[l.ids[o.prog][0]], ours[l.ids[o.prog][1]] = true, true
		}
	}
	var mine ebpf.ProgramID
	if l.links[key] != nil {
		mine = l.ids[h.prog][l.inst[key]]
	}
	var anchor link.Anchor
	if h.prog == "pre" {
		if mine != 0 && len(ids) > 0 && ids[0] == mine {
			return nil
		}
		anchor = link.Head()
	} else {
		_, seen := l.einat[key]
		// pre holds the head of tcx ingress, so einat is the program right after it
		var head ebpf.ProgramID
		if p := pinName(uplink, "pre"); h.attach == ebpf.AttachTCXIngress && l.links[p] != nil {
			head = l.ids["pre"][l.inst[p]]
		}
		e := einatProg(ids, ours, mine, l.einat[key], head, !seen)
		l.einat[key] = e
		i := slices.Index(ids, e)
		if mine != 0 && (e == 0 || i+1 < len(ids) && ids[i+1] == mine) {
			return nil
		}
		switch {
		case e != 0:
			anchor = link.AfterProgramByID(e)
		case h.attach == ebpf.AttachTCXIngress:
			pre := pinName(uplink, "pre")
			anchor = link.AfterProgram(l.progs["pre"][l.inst[pre]])
		default:
			anchor = link.Head()
		}
	}
	start := time.Now()
	path := filepath.Join(l.dir, key)
	next := 0
	if mine != 0 {
		next = 1 - l.inst[key]
	}
	ln, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: l.progs[h.prog][next], Attach: h.attach, Anchor: anchor})
	if err != nil {
		return fmt.Errorf("Attach %s: %w", key, err)
	}
	if mine != 0 {
		if err := l.links[key].Unpin(); err != nil {
			ln.Close()
			return fmt.Errorf("Unpin %s: %w", path, err)
		}
		l.links[key].Close()
		delete(l.links, key)
	}
	l.inst[key] = next
	if err := ln.Pin(path); err != nil {
		ln.Close()
		return fmt.Errorf("Pin %s: %w", path, err)
	}
	l.links[key] = ln
	if mine != 0 {
		slog.Info("Reordered", "uplink", uplink, "program", h.prog, "took", time.Since(start))
	}
	return nil
}

// einatProg finds the einat program among the programs of a hook (ids, in order; ours those of sandbox-uplink, mine
// the one to follow it, 0 when not attached, head the program of ours that holds the head of the hook, pre on tcx
// ingress and none on egress), knowing what the last round found (known; first when there was none). Its programs
// have no name to go by: reading one takes CAP_SYS_ADMIN (BPF_PROG_GET_FD_BY_ID). einat attaches at the head
// whenever it (re)attaches, so it is the known program while that is there, else a program of another at the head.
// In a first round einat attached ahead of what it found: the last program of another ahead of mine, or with mine
// not attached the first one. 0: einat isn't there
func einatProg(ids []ebpf.ProgramID, ours map[ebpf.ProgramID]bool, mine, known, head ebpf.ProgramID, first bool) ebpf.ProgramID {
	// einat sits where it attached, at the head: right after pre once that is back there, or at the head of egress.
	// A known program elsewhere was never einat but what a first round without einat took for it (Cilium alone on
	// the hook, at the tail, where post and egress then follow it behind Cilium), so revise
	if known != 0 && len(ids) > 0 {
		if head != 0 && ids[0] == head {
			if len(ids) > 1 && !ours[ids[1]] && ids[1] != known {
				return ids[1]
			}
		} else if head == 0 && !ours[ids[0]] && ids[0] != known {
			return ids[0]
		}
	}
	if known != 0 && slices.Contains(ids, known) {
		return known
	}
	if !first {
		if len(ids) > 0 && !ours[ids[0]] {
			return ids[0]
		}
		return 0
	}
	var e ebpf.ProgramID
	for _, id := range ids {
		if id == mine {
			break
		}
		if !ours[id] {
			if mine == 0 {
				return id
			}
			e = id
		}
	}
	return e
}

// attached says whether pre, post and egress are all attached on the uplink
func attached(links map[string]link.Link, uplink string) bool {
	for _, h := range hooks {
		if links[pinName(uplink, h.prog)] == nil {
			return false
		}
	}
	return true
}

// keep syncs every uplink and tends the sandboxes until ctx ends, every interval; ready runs after the first round.
// Only an uplink with all its programs attached is published: without egress a sandbox packet would leave it un-NATed
// while einat restarts
func (l *loader) keep(ctx context.Context, uplinks []string, interval time.Duration, ready func()) {
	for {
		var ok []string
		for _, u := range uplinks {
			if err := l.sync(u); err != nil {
				slog.Error("Sync", "uplink", u, "err", err)
			} else if attached(l.links, u) {
				ok = append(ok, u)
			}
		}
		l.sbx.tend(ok)
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
