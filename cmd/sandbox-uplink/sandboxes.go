package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/orbit-online/agent-sandbox/internal/uplink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sandboxes is what sandbox-uplink keeps for the netkit pairs of the sandboxes (cmd/netns-netkit): the uplinks map
// their `peer` programs redirect to and the gateways map they fall back to, forwarding on their primaries, and the
// registrations (mdns too) and pins of those that are gone
type sandboxes struct {
	dir      string
	uplinks  *ebpf.Map
	gateways *ebpf.Map
	reg      *ebpf.Map
	mdns     *ebpf.Map
	// Since when each primary without a pinned sandbox has been seen without one
	orphans map[uint32]time.Time
}

// How long a primary may go without a pinned sandbox before collect deletes it: far longer than an up takes from
// creating the pair to pinning, so only one whose up was killed (or stopped by its user) in between
const orphanGrace = 30 * time.Second

// openSandboxes pins the uplinks and gateways maps in dir (netkit.bpf.c has their shapes), or takes over the ones
// pinned there, readable by the group
func openSandboxes(dir string, reg, mdns *ebpf.Map) (*sandboxes, error) {
	ups, err := pinMap(dir, &ebpf.MapSpec{
		Name: filepath.Base(uplink.UplinksMap), Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: uplink.MaxUplinks,
	})
	if err != nil {
		return nil, err
	}
	gws, err := pinMap(dir, &ebpf.MapSpec{
		Name: filepath.Base(uplink.GatewaysMap), Type: ebpf.Array, KeySize: 4,
		ValueSize: uint32(binary.Size(uplink.Gateway{})), MaxEntries: 2,
	})
	if err != nil {
		return nil, err
	}
	return &sandboxes{dir, ups, gws, reg, mdns, map[uint32]time.Time{}}, nil
}

func pinMap(dir string, spec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec.Pinning = ebpf.PinByName
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
	// Pinned by a sandbox-uplink with another shape: replaced. Running sandboxes keep the old one until relaunched
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		if err := os.Remove(filepath.Join(dir, spec.Name)); err != nil {
			return nil, fmt.Errorf("Replace the %s map: %w", spec.Name, err)
		}
		m, err = ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
	}
	if err != nil {
		return nil, fmt.Errorf("Pin the %s map: %w", spec.Name, err)
	}
	if err := os.Chmod(filepath.Join(dir, spec.Name), 0o640); err != nil {
		return nil, fmt.Errorf("Open the %s map to its group: %w", spec.Name, err)
	}
	return m, nil
}

// tend runs after every sync of the uplinks
func (s *sandboxes) tend(uplinks []string) {
	if err := s.publish(uplinks); err != nil {
		slog.Error("Publish the uplinks", "err", err)
	}
	if err := s.forward(); err != nil {
		slog.Error("Forwarding on the primaries", "err", err)
	}
	if err := s.collect(); err != nil {
		slog.Error("Remove sandboxes that are gone", "err", err)
	}
}

// publish puts the ifindexes of the uplinks there now in the uplinks map, and nothing else, and per family the one
// among them with the default route of the lowest metric in the main table in the gateways map
func (s *sandboxes) publish(uplinks []string) error {
	want := map[uint32]bool{}
	for _, u := range uplinks {
		if iface, err := net.InterfaceByName(u); err == nil {
			want[uint32(iface.Index)] = true
		}
	}
	if err := uplink.DeleteIf(s.uplinks, func(k uint32, _ uint8) bool { return !want[k] }); err != nil {
		return err
	}
	for k := range want {
		if err := s.uplinks.Put(k, uint8(1)); err != nil {
			return err
		}
	}
	for i, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return fmt.Errorf("List the default routes: %w", err)
		}
		g := gateway(routes, want)
		if err := source(&g, family); err != nil {
			return err
		}
		if err := s.gateways.Put(uint32(i), g); err != nil {
			return err
		}
	}
	return nil
}

// source fills in the address and MAC of the uplink of g that mDNS queries leave from: the first IPv4 address, or the
// IPv6 link-local one, which RFC 6762 answers on the link
func source(g *uplink.Gateway, family int) error {
	if g.Ifindex == 0 {
		return nil
	}
	l, err := netlink.LinkByIndex(int(g.Ifindex))
	if err != nil {
		return fmt.Errorf("Find uplink %d: %w", g.Ifindex, err)
	}
	copy(g.MAC[:], l.Attrs().HardwareAddr)
	addrs, err := netlink.AddrList(l, family)
	if err != nil {
		return fmt.Errorf("List the addresses of %s: %w", l.Attrs().Name, err)
	}
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if ok && (family == netlink.FAMILY_V4 || ip.IsLinkLocalUnicast()) {
			g.Src = ip.Unmap().As16()
			break
		}
	}
	return nil
}

// gateway picks the default route of the lowest metric through one of uplinks
func gateway(routes []netlink.Route, uplinks map[uint32]bool) uplink.Gateway {
	var best *netlink.Route
	for i, r := range routes {
		if uplinks[uint32(r.LinkIndex)] && (best == nil || r.Priority < best.Priority) {
			best = &routes[i]
		}
	}
	if best == nil {
		return uplink.Gateway{}
	}
	g := uplink.Gateway{Ifindex: uint32(best.LinkIndex)}
	if gw, ok := netip.AddrFromSlice(best.Gw); ok {
		g.Addr = gw.Unmap().As16()
	}
	return g
}

// forward puts forwarding back on the primaries where it's off: setting all.forwarding resets it on every device, and
// bpf_fib_lookup in their `peer` programs refuses without it (FWD_DISABLED, failing closed meanwhile)
func (s *sandboxes) forward() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("List the devices: %w", err)
	}
	for _, l := range links {
		if !isPrimary(l) {
			continue
		}
		on, err := uplink.Forward(l.Attrs().Name)
		// Gone meanwhile
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if len(on) > 0 {
			slog.Info("Forwarding back on", "primary", l.Attrs().Name, "families", on)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func isPrimary(l netlink.Link) bool {
	return l.Type() == "netkit" && strings.HasPrefix(l.Attrs().Name, uplink.PrimaryPrefix)
}

// gone says whether the device of ifindex is gone. Asked after reading what names it: ifindexes aren't reused soon
func gone(ifindex uint32) bool {
	_, err := netlink.LinkByIndex(int(ifindex))
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

// notPrimary says whether the device of ifindex is gone or isn't a primary: another device got the ifindex
func notPrimary(ifindex uint32) bool {
	l, err := netlink.LinkByIndex(int(ifindex))
	if err != nil {
		var nf netlink.LinkNotFoundError
		return errors.As(err, &nf)
	}
	return !isPrimary(l)
}

// collect removes the registrations whose primary is gone, the mdns ones whose ifindex names no primary, the pins
// of sandboxes that ended without netns-netkit down (the launcher crashed), and primaries that went without pins for
// orphanGrace (their up killed in between), which hold routes to their addresses
func (s *sandboxes) collect() error {
	if err := uplink.DeleteIf(s.mdns, func(p uint32, _ uint8) bool { return notPrimary(p) }); err != nil {
		return err
	}
	err := uplink.DeleteIf(s.reg, func(k [16]byte, v uint32) bool {
		if !gone(v) {
			return false
		}
		slog.Info("Unregister", "addr", netip.AddrFrom16(k).Unmap(), "ifindex", v)
		return true
	})
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	pinned := map[uint32]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.dir, e.Name())
		if p, err := primaryOf(dir); err == nil {
			pinned[p] = true
		}
		removed, err := removeGone(dir, primaryOf, gone)
		if err != nil {
			return err
		}
		if removed {
			slog.Info("Removed the pins of a sandbox that is gone", "dir", dir)
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("List the devices: %w", err)
	}
	primaries := map[uint32]netlink.Link{}
	for _, l := range links {
		if isPrimary(l) {
			primaries[uint32(l.Attrs().Index)] = l
		}
	}
	for _, p := range orphaned(s.orphans, slices.Collect(maps.Keys(primaries)), pinned, time.Now()) {
		slog.Info("Deleting a primary without pins", "primary", primaries[p].Attrs().Name)
		if err := netlink.LinkDel(primaries[p]); err != nil && !errors.Is(err, unix.ENODEV) {
			return fmt.Errorf("Delete %s: %w", primaries[p].Attrs().Name, err)
		}
	}
	return nil
}

// orphaned returns the primaries that pinned names none of for longer than orphanGrace, keeping in since when each was
// first seen so
func orphaned(since map[uint32]time.Time, primaries []uint32, pinned map[uint32]bool, now time.Time) []uint32 {
	var old []uint32
	seen := map[uint32]bool{}
	for _, p := range primaries {
		if pinned[p] {
			continue
		}
		seen[p] = true
		if t, ok := since[p]; !ok {
			since[p] = now
		} else if now.Sub(t) > orphanGrace {
			old = append(old, p)
		}
	}
	maps.DeleteFunc(since, func(p uint32, _ time.Time) bool { return !seen[p] })
	return old
}

// primaryOf reads the primary of the sandbox of dir. Missing while netns-netkit pins it, which it does once the
// primary is there
func primaryOf(dir string) (uint32, error) {
	sb, err := uplink.ReadSandbox(dir)
	return sb.Primary, err
}

// removeGone removes dir when the primary it names is gone, and still names it when read again right before: an up of
// the same launcher may have put a new sandbox there meanwhile, whose pins hold its programs on
func removeGone(dir string, primaryOf func(string) (uint32, error), gone func(uint32) bool) (bool, error) {
	p, err := primaryOf(dir)
	if err != nil || !gone(p) {
		return false, nil
	}
	if again, err := primaryOf(dir); err != nil || again != p {
		return false, nil
	}
	return true, os.RemoveAll(dir)
}
