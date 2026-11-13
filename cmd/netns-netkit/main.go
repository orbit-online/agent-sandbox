package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
the uid of the caller and <name>), for the caller to put on eth0. Programs on
the pair let the sandbox reach the network through the einat uplinks alone,
and only processes of the caller on the host reach the ports granted. <pid>
must belong to the caller, and its network namespace to a user namespace below
that of the caller, through a child of it that the caller owns: owning that
child, the caller holds every capability over the network namespace,
cap_net_admin included. What an earlier sandbox of <name> left goes first.
With --mdns, the mDNS queries of the sandbox go out of the uplink with the
default route, from the address of that uplink and port 5353, and the mDNS
responses from the LAN come in.

down deletes the pair of <name> (gone with the network namespace already,
unless the sandbox still runs), its registration and its pins. addr prints the
addresses of the running sandbox of <name>, as up did. uplinks prints the
ifindexes of the einat uplinks with the default route of IPv4 and of IPv6, 0
for none, as sandbox-uplink publishes them. grant lets the host reach a port
of the sandbox over TCP or UDP; over UDP the sandbox answers only a host
client with a connected socket (an unconnected sendto gets nothing). revoke
ends that and the connections made under it, or with --all every grant and
connection.

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
	// Counted and registered under the lock of the uid, so two ups of one uid at once can't both pass the limit, and
	// a stopped up holds back only its own user
	unlock, err := lock(uplink.PinDir, uid)
	if err != nil {
		return err
	}
	defer unlock()
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("List the devices: %w", err)
	}
	var names []string
	for _, l := range links {
		names = append(names, l.Attrs().Name)
	}
	n, err := sandboxCount(uplink.PinDir, uid, names)
	if err != nil {
		return err
	}
	if n >= uplink.MaxSandboxesPerUID {
		return fmt.Errorf("Uid %d runs %d sandboxes already, the most netns-netkit sets up for one user", uid, n)
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
	sb := uplink.Sandbox{V4: v4.As16(), V6: v6.As16(), Primary: uint32(link.Attrs().Index), UID: uint32(uid)}
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

// lock takes an exclusive flock on lock-<uid> in pinDir, a dir of uid it creates on first use (bpffs holds no files),
// until the returned func runs
func lock(pinDir string, uid int) (func(), error) {
	dir := filepath.Join(pinDir, "lock-"+strconv.Itoa(uid))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("Create %s: %w", dir, err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("Open %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Uid != uint32(uid) {
		unix.Close(fd)
		return nil, fmt.Errorf("%s is not a dir of uid %d: %v", dir, uid, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("Lock %s: %w", dir, err)
	}
	return func() { unix.Close(fd) }, nil
}

// sandboxCount counts the sandboxes of uid: its dirs in pinDir (uplink.SandboxDir), which sandbox-uplink removes once
// their primary is gone, and among devices its primaries without one (an up killed before it pinned), which
// sandbox-uplink deletes after a while
func sandboxCount(pinDir string, uid int, devices []string) (int, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return 0, fmt.Errorf("List the sandboxes: %w", err)
	}
	id, primaries := strconv.Itoa(uid), map[string]bool{}
	for _, e := range entries {
		if name, ok := strings.CutPrefix(e.Name(), id); e.IsDir() && ok && (name == "" || name[0] == '-') {
			primaries[primaryName(uplink.PrimaryPrefix, uid, strings.TrimPrefix(name, "-"))] = true
		}
	}
	// As primaryName has it, at most 12 bytes for a 32-bit uid
	prefix := uplink.PrimaryPrefix + strconv.FormatInt(int64(uid), 36) + "-"
	for _, d := range devices {
		if strings.HasPrefix(d, prefix) {
			primaries[d] = true
		}
	}
	return len(primaries), nil
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
	v6Block, err := uplink.ULABlock()
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
