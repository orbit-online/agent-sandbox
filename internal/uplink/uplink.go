// Package uplink is what sandbox-uplink and the per-launcher helper share: the sandboxes' address blocks, the name
// prefix of the netkit primaries, and where and how the helper registers a sandbox address with the uplink programs
// (cmd/sandbox-uplink/uplink.bpf.c)
package uplink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	// The bpffs instance sandbox-uplink pins in, mounted by the NixOS module for its user and group alone
	PinDir = "/run/sandbox-uplink"
	// The registration map, pinned by name in PinDir: an address (16 bytes in network order, IPv4 mapped into
	// ::ffff:0:0/96, as netip.Addr.As16 has it) -> the ifindex of the netkit primary (uint32, host byte order).
	// Group sandbox-uplink, mode 0660
	SandboxesMap = PinDir + "/sandboxes"
	// The einat uplinks, pinned by sandbox-uplink for the `peer` programs: ifindex (uint32) -> 1 (uint8), at most
	// MaxUplinks, which netns-netkit sets on the map of netkit.bpf.c. Group sandbox-uplink, mode 0640
	UplinksMap = PinDir + "/uplinks"
	MaxUplinks = 64
	// Per family (0 IPv4, 1 IPv6) the einat uplink that carries the default route of the main table and its gateway
	// (Gateway), pinned by sandbox-uplink beside UplinksMap: where the `peer` programs send what the host routes through
	// another device. Group sandbox-uplink, mode 0640
	GatewaysMap = PinDir + "/gateways"
	// The netkit primaries of the sandboxes that take mDNS responses, pinned by name beside SandboxesMap: ifindex
	// (uint32) -> 1 (uint8). Group sandbox-uplink, mode 0660
	MdnsMap = PinDir + "/mdns"
	// The netkit primaries' names start with this, which the NixOS module keeps dhcpcd and NetworkManager off
	PrimaryPrefix = "sbx-"
	// The map in each SandboxDir that describes its sandbox (Sandbox), group-readable, so sandbox-uplink finds the
	// sandboxes that are gone
	SandboxMap = "sandbox"
	// The sandboxes netns-netkit sets up for one uid at a time, so no user fills the registration map (two entries
	// each) for the others
	MaxSandboxesPerUID = 16
)

// SandboxDir is where netns-netkit pins the programs and maps of the sandbox of launcher name (empty for the default
// one) of uid: owner uid, group sandbox-uplink, mode 0770
func SandboxDir(uid int, name string) string {
	if name == "" {
		return fmt.Sprintf("%s/%d", PinDir, uid)
	}
	return fmt.Sprintf("%s/%d-%s", PinDir, uid, name)
}

// Gateway is a value of GatewaysMap (struct gateway in cmd/netns-netkit/netkit.bpf.c): the ifindex of the uplink, 0 for
// none, the gateway as As16 has it, zero for a default route without one, and the source and MAC mDNS queries leave the
// uplink with: the first IPv4 address, the IPv6 link-local one, zero for none
type Gateway struct {
	Ifindex   uint32
	Addr, Src [16]byte
	MAC       [6]byte
	_         [2]byte
}

// Sandbox is the one value of SandboxMap (struct sandbox in cmd/netns-netkit/netkit.bpf.c): the addresses of the sandbox
// as As16 has them, the ifindex of its netkit primary, and the uid of its owner, whose processes alone reach its granted
// ports
type Sandbox struct {
	V4, V6       [16]byte
	Primary, UID uint32
}

// The sandboxes' IPv4 addresses, a /32 each. RFC 3927 link-local, clear of the blocks clouds and Kubernetes use
var V4Block = netip.MustParsePrefix("169.254.100.0/22")

// Keyed by the machine ID, as machine-id(5) asks of an application-specific ID
var appID, _ = hex.DecodeString("0840b57391704da6960f221fb40de13b")

// ULABlock is the sandboxes' IPv6 /48 on this machine (RFC 4193): fd, then a Global ID of the first 40 bits of
// HMAC-SHA256 keyed by the machine ID (/etc/machine-id) over the app ID of this package. Narrow, so the ULA prefix of a
// LAN stays with the host
func ULABlock() (netip.Prefix, error) {
	id, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("Read machine ID: %w", err)
	}
	return ulaBlock(string(id))
}

func ulaBlock(machineID string) (netip.Prefix, error) {
	id, err := hex.DecodeString(strings.TrimSpace(machineID))
	if err != nil || len(id) != 16 {
		return netip.Prefix{}, fmt.Errorf("Parse machine ID %q: not 32 hex digits", strings.TrimSpace(machineID))
	}
	mac := hmac.New(sha256.New, id)
	mac.Write(appID)
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:6], mac.Sum(nil))
	return netip.PrefixFrom(netip.AddrFrom16(a), 48), nil
}

// ReadSandbox reads the Sandbox of the sandbox dir
func ReadSandbox(dir string) (Sandbox, error) {
	var sb Sandbox
	m, err := ebpf.LoadPinnedMap(filepath.Join(dir, SandboxMap), &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return sb, err
	}
	defer m.Close()
	return sb, m.Lookup(uint32(0), &sb)
}

// DeleteIf deletes the entries of m that drop picks, read first and deleted after: deleting while iterating a hash map
// restarts the walk
func DeleteIf[K, V any](m *ebpf.Map, drop func(K, V) bool) error {
	var keys []K
	var k K
	var v V
	it := m.Iterate()
	for it.Next(&k, &v) {
		if drop(k, v) {
			keys = append(keys, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

// Forward turns IPv4 and IPv6 forwarding on for dev where it is off, and returns the families it turned it on for.
// bpf_fib_lookup in the `peer` program refuses without it on the primary (FWD_DISABLED)
func Forward(dev string) ([]string, error) {
	var on []string
	for _, f := range []string{"ipv4", "ipv6"} {
		path := "/proc/sys/net/" + f + "/conf/" + dev + "/forwarding"
		b, err := os.ReadFile(path)
		if err != nil {
			return on, fmt.Errorf("Read %s forwarding of %s: %w", f, dev, err)
		}
		if strings.TrimSpace(string(b)) != "0" {
			continue
		}
		if err := os.WriteFile(path, []byte("1"), 0); err != nil {
			return on, fmt.Errorf("Turn %s forwarding on for %s: %w", f, dev, err)
		}
		on = append(on, f)
	}
	return on, nil
}
