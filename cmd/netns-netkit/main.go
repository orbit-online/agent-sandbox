package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/journal"
	"github.com/orbit-online/agent-sandbox/internal/uplink"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const usage = `netns-netkit - Connect a user-owned network namespace to the network through a netkit pair

Usage:
  netns-netkit up [--name=<name>] [--mdns] <pid>
  netns-netkit down [--name=<name>]
  netns-netkit addr [--name=<name>]
  netns-netkit uplinks
  netns-netkit grant [--name=<name>] (tcp|udp) <port>
  netns-netkit revoke [--name=<name>] (--all | (tcp|udp) <port>)

up creates eth0 in the network namespace of <pid>, the peer of a netkit pair
whose primary stays in the host netns, and prints the addresses of the sandbox
(an IPv4 /32 and an IPv6 /128 from the blocks of sandbox-uplink, by a hash of
the uid of the caller and <name>), for the caller to put on eth0. Programs on the
pair let the sandbox reach the network through the einat uplinks alone, and
the host reach the ports granted. <pid> must belong to the caller, and its
network namespace must lie in a user namespace below the caller's whose
topmost one below the caller's the caller owns: the caller then holds every
capability over it by owning that user namespace, cap_net_admin included.
What an earlier sandbox of <name> left goes first. With --mdns, the mDNS
queries of the sandbox go out of the uplink with the default route, from the
address of that uplink and port 5353, and the mDNS responses from the LAN
come in.

down ends what up set up for <name>, once the sandbox ended. addr prints the
addresses of the running sandbox of <name>, as up did. uplinks prints the
ifindexes of the einat uplinks with the default route of IPv4 and of IPv6, 0
for none, as sandbox-uplink publishes them. grant lets the host
reach a port of the sandbox over TCP or UDP, revoke ends that and the
connections made under it, or with --all every grant and connection.

Options:
  --name=<name>  The name of the launcher, empty for the default launcher
  --all          Every port granted
  --mdns         Copy mDNS queries out and responses in
`

// What a launcher name may be (the assertion of the module), so it makes a pin name
var launcherName = regexp.MustCompile(`^([a-z][a-z0-9-]{0,45})?$`)

func main() {
	journal.Setup()
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	if err := run(opts); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(opts docopt.Opts) error {
	name, _ := opts.String("--name")
	if !launcherName.MatchString(name) {
		return fmt.Errorf("Launcher name %q is not [a-z][a-z0-9-]*, at most 46 characters", name)
	}
	grants := opts["grant"] == true || opts["revoke"] == true
	all := opts["--all"] == true
	var port uint64
	if grants && !all {
		var err error
		port, err = strconv.ParseUint(opts["<port>"].(string), 10, 16)
		if err != nil || port == 0 {
			return fmt.Errorf("Port %q is not 1 to 65535", opts["<port>"])
		}
	}
	if err := humanCaller(); err != nil {
		return err
	}
	if opts["uplinks"] == true {
		return printUplinks()
	}
	uid := unix.Getuid()
	dir := uplink.SandboxDir(uid, name)
	if opts["addr"] == true {
		return printAddr(dir)
	}
	if all {
		return revokeAll(dir)
	}
	if grants {
		proto := "udp"
		if opts["tcp"] == true {
			proto = "tcp"
		}
		return grant(dir, proto, uint16(port), opts["grant"] == true)
	}
	reg, err := ebpf.LoadPinnedMap(uplink.SandboxesMap, nil)
	if err != nil {
		return fmt.Errorf("Open %s (is sandbox-uplink running?): %w", uplink.SandboxesMap, err)
	}
	defer reg.Close()
	primary := primaryName(uplink.PrimaryPrefix, uid, name)
	if opts["down"] == true {
		// Gone with the sandbox netns already, unless the sandbox still runs
		if err := delPrimary(primary); err != nil {
			return err
		}
		return remove(reg, dir)
	}
	pid, err := strconv.Atoi(opts["<pid>"].(string))
	if err != nil {
		return fmt.Errorf("Parse <pid>: %w", err)
	}
	return up(reg, uid, pid, name, primary, dir, opts["--mdns"] == true)
}

// humanCaller refuses callers outside group users: the wrapper is setgid sandbox-uplink, which takes the group of the
// file, so the group can't limit who runs it. Whoever runs it gives their own namespaces a network outside the host
// firewall
func humanCaller() error {
	g, err := user.LookupGroup("users")
	if err != nil {
		return fmt.Errorf("Look up group users: %w", err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	groups, err := unix.Getgroups()
	if err != nil {
		return fmt.Errorf("Read the groups of the caller: %w", err)
	}
	if unix.Getgid() != gid && !slices.Contains(groups, gid) {
		return errors.New("Only members of group users may run netns-netkit")
	}
	return nil
}

func up(reg *ebpf.Map, uid, pid int, name, primary, dir string, mdns bool) (err error) {
	netnsFd, err := openNetns(pid, uid, "/proc/self/ns/user")
	if err != nil {
		return err
	}
	defer unix.Close(netnsFd)
	// What a sandbox of this launcher that ended without down left: its primary too while the kernel still tears its
	// netns down. Of the caller, by the uid in the name
	if err := delPrimary(primary); err != nil {
		return err
	}
	if err := remove(reg, dir); err != nil {
		return err
	}
	v4, v6, err := addresses(reg, uid, name)
	if err != nil {
		return err
	}
	link, err := addPair(primary, netnsFd)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			netlink.LinkDel(link)
			remove(reg, dir)
		}
	}()
	if err := routePair(link, v4, v6); err != nil {
		return err
	}
	sb := uplink.Sandbox{V4: uplink.Key(v4), V6: uplink.Key(v6), Primary: uint32(link.Attrs().Index)}
	if err := attach(dir, sb, mdns); err != nil {
		return err
	}
	if err := register(reg, sb, mdns); err != nil {
		return err
	}
	slog.Info("Up", "primary", primary, "ipv4", v4, "ipv6", v6)
	fmt.Println(v4, v6)
	return nil
}

// delPrimary deletes the primary of that name, and with it the peer, when it's there
func delPrimary(name string) error {
	l, err := netlink.LinkByName(name)
	var nf netlink.LinkNotFoundError
	if errors.As(err, &nf) {
		return nil
	}
	if err == nil {
		err = netlink.LinkDel(l)
	}
	if err != nil && !errors.Is(err, unix.ENODEV) {
		return fmt.Errorf("Delete %s: %w", name, err)
	}
	return nil
}

// addresses picks the addresses of the sandbox, past those of the host and the other sandboxes
func addresses(reg *ebpf.Map, uid int, name string) (netip.Addr, netip.Addr, error) {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("Read machine ID: %w", err)
	}
	v6Block, err := uplink.ULABlock(string(machineID))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	taken, err := hostAddrs()
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	others, err := registered(reg)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	isTaken := func(a netip.Addr) bool { return taken[a] || others[a] }
	s := seed(uid, name)
	v4, err := pick(uplink.V4Block, s, isTaken)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	v6, err := pick(v6Block, s, isTaken)
	return v4, v6, err
}
