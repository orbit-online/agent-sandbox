package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/orbit-online/agent-sandbox/internal/uplink"
)

// Set by the package to the compiled netkit.bpf.c
var object string

// The pins in a sandbox dir besides uplink.SandboxMap: the links of the programs and the port-forwarding maps
var (
	attachments = map[string]ebpf.AttachType{"peer": ebpf.AttachNetkitPeer, "primary": ebpf.AttachNetkitPrimary}
	pinnedMaps  = []string{uplink.SandboxMap, "ports", "flows"}
)

// The protocols a port is granted for, as the programs number them
var protocols = map[string]uint8{"tcp": 6, "udp": 17}

// attach loads the programs for the sandbox sb, attaches them through its primary and pins them and their maps in dir,
// where they stay attached after this process ends. The uplinks and gateways maps are the ones sandbox-uplink keeps
// current
func attach(dir string, sb uplink.Sandbox) error {
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		return fmt.Errorf("Read %s: %w", object, err)
	}
	replace := map[string]*ebpf.Map{}
	for name, path := range map[string]string{"uplinks": uplink.UplinksMap, "gateways": uplink.GatewaysMap} {
		m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			return fmt.Errorf("Open %s (is sandbox-uplink running?): %w", path, err)
		}
		defer m.Close()
		replace[name] = m
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: replace})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			slog.Error("Verifier", "log", fmt.Sprintf("%+v", ve))
		}
		return fmt.Errorf("Load %s: %w", object, err)
	}
	defer coll.Close()
	// Before the dir: a pinned sandbox map names a primary, which sandbox-uplink removes the dir after
	if err := coll.Maps[uplink.SandboxMap].Put(uint32(0), sb); err != nil {
		return fmt.Errorf("Describe the sandbox: %w", err)
	}
	if err := os.Mkdir(dir, 0); err != nil {
		return fmt.Errorf("Create %s: %w", dir, err)
	}
	// The group, sandbox-uplink, removes it once the primary is gone
	if err := os.Chmod(dir, 0o770); err != nil {
		return fmt.Errorf("Open %s to its group: %w", dir, err)
	}
	for _, m := range pinnedMaps {
		if err := coll.Maps[m].Pin(filepath.Join(dir, m)); err != nil {
			return fmt.Errorf("Pin %s: %w", m, err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, uplink.SandboxMap), 0o640); err != nil {
		return fmt.Errorf("Open the sandbox map to its group: %w", err)
	}
	for prog, at := range attachments {
		l, err := link.AttachNetkit(link.NetkitOptions{Interface: int(sb.Primary), Program: coll.Programs[prog], Attach: at})
		if err != nil {
			return fmt.Errorf("Attach %s: %w", prog, err)
		}
		defer l.Close()
		if err := l.Pin(filepath.Join(dir, prog)); err != nil {
			return fmt.Errorf("Pin %s: %w", prog, err)
		}
	}
	return nil
}

// registered reads the registration map: the addresses of every sandbox
func registered(reg *ebpf.Map) (map[netip.Addr]bool, error) {
	m := map[netip.Addr]bool{}
	var k [16]byte
	var v uint32
	it := reg.Iterate()
	for it.Next(&k, &v) {
		m[netip.AddrFrom16(k).Unmap()] = true
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("Read %s: %w", uplink.SandboxesMap, err)
	}
	return m, nil
}

// register hands the addresses of sb to the uplink programs, which deliver the replies to them
func register(reg *ebpf.Map, sb uplink.Sandbox) error {
	for _, k := range [][16]byte{sb.V4, sb.V6} {
		if err := reg.Update(k, sb.Primary, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("Register %v: %w", netip.AddrFrom16(k).Unmap(), err)
		}
	}
	return nil
}

// remove ends what dir describes: the registration of its addresses, where they still name its primary, and its pins,
// which detaches the programs when the primary is still there (both ends then drop everything). Nothing there is
// fine
func remove(reg *ebpf.Map, dir string) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, uplink.SandboxMap), nil)
	if errors.Is(err, os.ErrNotExist) {
		return removePins(dir)
	}
	if err != nil {
		return fmt.Errorf("Open %s: %w", dir, err)
	}
	var sb uplink.Sandbox
	err = m.Lookup(uint32(0), &sb)
	m.Close()
	if err != nil {
		return fmt.Errorf("Read %s: %w", dir, err)
	}
	for _, k := range [][16]byte{sb.V4, sb.V6} {
		var v uint32
		if reg.Lookup(k, &v) == nil && v == sb.Primary {
			if err := reg.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("Unregister %v: %w", netip.AddrFrom16(k).Unmap(), err)
			}
		}
	}
	return removePins(dir)
}

func removePins(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("Remove %s: %w", dir, err)
	}
	return nil
}

// grant lets the host reach port over proto in the sandbox of dir; revoke ends that and the flows recorded on it
func grant(dir, proto string, port uint16, on bool) error {
	key := uint32(protocols[proto])<<16 | uint32(port)
	ports, err := ebpf.LoadPinnedMap(filepath.Join(dir, "ports"), nil)
	if err != nil {
		return fmt.Errorf("Open the ports of %s (does the sandbox run?): %w", dir, err)
	}
	defer ports.Close()
	if on {
		if err := ports.Put(key, uint8(1)); err != nil {
			return fmt.Errorf("Grant %s port %d: %w", proto, port, err)
		}
		return nil
	}
	if err := ports.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("Revoke %s port %d: %w", proto, port, err)
	}
	return clearFlows(dir, protocols[proto], port)
}

// The key of the flows map (struct flow)
type flow struct {
	Host           [16]byte
	Port, HostPort uint16
	Proto          uint8
	_              [3]uint8
}

// clearFlows deletes the flows recorded on port over proto, after the grant is gone, so none comes back
func clearFlows(dir string, proto uint8, port uint16) error {
	flows, err := ebpf.LoadPinnedMap(filepath.Join(dir, "flows"), nil)
	if err != nil {
		return fmt.Errorf("Open the flows of %s: %w", dir, err)
	}
	defer flows.Close()
	var stale []flow
	var f flow
	var v uint8
	it := flows.Iterate()
	for it.Next(&f, &v) {
		if f.Proto == proto && f.Port == port {
			stale = append(stale, f)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("Read the flows of %s: %w", dir, err)
	}
	for _, f := range stale {
		if err := flows.Delete(f); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("Delete a flow of %s: %w", dir, err)
		}
	}
	return nil
}
