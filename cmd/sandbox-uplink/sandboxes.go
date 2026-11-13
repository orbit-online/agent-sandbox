package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/orbit-online/agent-sandbox/internal/uplink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// sandboxes is what sandbox-uplink keeps for the netkit pairs of the sandboxes (cmd/netns-netkit): the uplinks map
// their PEER programs redirect to and the gateways map they fall back to, forwarding on their primaries, and the
// registrations and pins of those that are gone
type sandboxes struct {
	dir      string
	uplinks  *ebpf.Map
	gateways *ebpf.Map
	reg      *ebpf.Map
}

// openSandboxes pins the uplinks and gateways maps in dir (netkit.bpf.c has their shapes), or takes over the ones
// pinned there, readable by the group
func openSandboxes(dir string, reg *ebpf.Map) (*sandboxes, error) {
	ups, err := pinMap(dir, &ebpf.MapSpec{
		Name: filepath.Base(uplink.UplinksMap), Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: uplink.MaxUplinks,
	})
	if err != nil {
		return nil, err
	}
	gws, err := pinMap(dir, &ebpf.MapSpec{
		Name: filepath.Base(uplink.GatewaysMap), Type: ebpf.Array, KeySize: 4, ValueSize: 20, MaxEntries: 2,
	})
	if err != nil {
		return nil, err
	}
	return &sandboxes{dir, ups, gws, reg}, nil
}

func pinMap(dir string, spec *ebpf.MapSpec) (*ebpf.Map, error) {
	spec.Pinning = ebpf.PinByName
	m, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: dir})
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
	var k uint32
	var v uint8
	var stale []uint32
	it := s.uplinks.Iterate()
	for it.Next(&k, &v) {
		if !want[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range stale {
		if err := s.uplinks.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
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
		if err := s.gateways.Put(uint32(i), gateway(routes, want)); err != nil {
			return err
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
		g.Addr = uplink.Key(gw.Unmap())
	}
	return g
}

// forward puts forwarding back on the primaries where it's off: setting all.forwarding resets it on every device, and
// bpf_fib_lookup in their PEER programs refuses without it (FWD_DISABLED, failing closed meanwhile)
func (s *sandboxes) forward() error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("List the devices: %w", err)
	}
	for _, l := range links {
		name := l.Attrs().Name
		if l.Type() != "netkit" || !strings.HasPrefix(name, uplink.PrimaryPrefix) {
			continue
		}
		for _, f := range []string{"ipv4", "ipv6"} {
			path := "/proc/sys/net/" + f + "/conf/" + name + "/forwarding"
			b, err := os.ReadFile(path)
			if err != nil || strings.TrimSpace(string(b)) != "0" {
				continue // Gone meanwhile, or on
			}
			if err := os.WriteFile(path, []byte("1"), 0); err != nil {
				return fmt.Errorf("Turn %s forwarding on for %s: %w", f, name, err)
			}
			slog.Info("Forwarding back on", "primary", name, "family", f)
		}
	}
	return nil
}

// gone says whether the device of ifindex is gone. Asked after reading what names it: ifindexes aren't reused soon
func gone(ifindex uint32) bool {
	_, err := netlink.LinkByIndex(int(ifindex))
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

// collect removes the registrations whose primary is gone, and the pins of sandboxes that ended without netns-netkit
// down (the launcher crashed)
func (s *sandboxes) collect() error {
	var k [16]byte
	var v uint32
	stale := map[[16]byte]uint32{}
	it := s.reg.Iterate()
	for it.Next(&k, &v) {
		stale[k] = v
	}
	if err := it.Err(); err != nil {
		return err
	}
	for k, v := range stale {
		if gone(v) {
			if err := s.reg.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
			slog.Info("Unregistered", "addr", netip.AddrFrom16(k).Unmap(), "ifindex", v)
		}
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.dir, e.Name())
		// Missing while netns-netkit pins it, which it does once the primary is there
		m, err := ebpf.LoadPinnedMap(filepath.Join(dir, uplink.SandboxMap), &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			continue
		}
		var sb uplink.Sandbox
		err = m.Lookup(uint32(0), &sb)
		m.Close()
		if err != nil || !gone(sb.Primary) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		slog.Info("Removed the pins of a sandbox that is gone", "dir", dir)
	}
	return nil
}
