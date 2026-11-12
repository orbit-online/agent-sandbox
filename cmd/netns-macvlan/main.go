package main

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"unsafe"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/journal"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const usage = `netns-macvlan - Give a user-owned network namespace its own macvlan on the LAN

Usage:
  netns-macvlan <pid> [<name>]

Creates eth0 in the network namespace of <pid>: a macvlan in private mode on
the device carrying the default route, with a MAC derived from the machine ID,
the caller's uid and <name>, which tells one sandbox of the caller from
another. <pid> must belong to the caller, and its network namespace must lie
in a user namespace below the caller's whose topmost one below the caller's
the caller owns: the caller then holds every capability over it by owning
that user namespace, cap_net_admin included.
`

func main() {
	journal.Setup()
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	pid, err := opts.Int("<pid>")
	if err != nil {
		slog.Error("Parse <pid>", "err", err)
		os.Exit(2)
	}
	name, _ := opts.String("<name>")
	if err := run(pid, name); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(pid int, name string) error {
	uid := unix.Getuid()
	netnsFd, err := openNetns(pid, uid, "/proc/self/ns/user")
	if err != nil {
		return err
	}
	defer unix.Close(netnsFd)
	parent, err := defaultRouteLink()
	if err != nil {
		return err
	}
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return fmt.Errorf("Read machine ID: %w", err)
	}
	mac := stableMAC(machineID, uid, name)
	link := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:         "eth0",
			ParentIndex:  parent,
			HardwareAddr: mac,
			Namespace:    netlink.NsFd(netnsFd),
		},
		Mode: netlink.MACVLAN_MODE_PRIVATE,
	}
	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("Create macvlan: %w", err)
	}
	return nil
}

// Opens the network namespace of pid after checking that the caller, of uid in user namespace ownUserns (a path),
// may hand it a LAN interface
func openNetns(pid, uid int, ownUserns string) (int, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, fmt.Errorf("Open pidfd for %d: %w", pid, err)
	}
	defer unix.Close(pidfd)
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid), &st); err != nil {
		return -1, fmt.Errorf("Stat process %d: %w", pid, err)
	}
	if int(st.Uid) != uid {
		return -1, fmt.Errorf("Process %d belongs to uid %d, not %d", pid, st.Uid, uid)
	}
	netnsFd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("Open network namespace of %d: %w", pid, err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(netnsFd)
		}
	}()
	// The pidfd outlives a recycled pid, so a successful signal 0 means the checks above were about this process
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return -1, fmt.Errorf("Process %d exited during checks: %w", pid, err)
	}
	var own unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &own); err != nil {
		return -1, fmt.Errorf("Stat own network namespace: %w", err)
	}
	if err := unix.Fstat(netnsFd, &st); err != nil {
		return -1, fmt.Errorf("Stat network namespace of %d: %w", pid, err)
	}
	if st.Dev == own.Dev && st.Ino == own.Ino {
		return -1, fmt.Errorf("Process %d shares the caller's network namespace", pid)
	}
	usernsFd, err := unix.IoctlRetInt(netnsFd, unix.NS_GET_USERNS)
	if err != nil {
		return -1, fmt.Errorf("Get user namespace owning the network namespace of %d: %w", pid, err)
	}
	defer unix.Close(usernsFd)
	if err := ownedBelow(usernsFd, ownUserns, uid); err != nil {
		return -1, fmt.Errorf("Network namespace of %d %w", pid, err)
	}
	ok = true
	return netnsFd, nil
}

// Checks that the user namespace usernsFd lies below ownUserns, and that the one right below ownUserns on the way
// there is owned by uid. By the owner rule that uid then holds every capability in it and in everything below, whoever
// owns those: the immediate owner alone would pass a user namespace of the caller's below one a privileged process
// made and mapped the caller's uid into
func ownedBelow(usernsFd int, ownUserns string, uid int) error {
	var own unix.Stat_t
	if err := unix.Stat(ownUserns, &own); err != nil {
		return fmt.Errorf("can't be checked: stat own user namespace: %w", err)
	}
	fd, err := unix.Dup(usernsFd)
	if err != nil {
		return fmt.Errorf("can't be checked: %w", err)
	}
	defer func() { unix.Close(fd) }()
	if same(fd, own) {
		return fmt.Errorf("is owned by the caller's own user namespace")
	}
	// The kernel nests at most 32 user namespaces
	for range 33 {
		parent, err := unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
		if err != nil {
			// EPERM: fd is the caller's user namespace or above it, which the walk passed without meeting the caller's
			return fmt.Errorf("isn't below the caller's user namespace: %w", err)
		}
		if same(parent, own) {
			unix.Close(parent)
			var owner uint32
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.NS_GET_OWNER_UID, uintptr(unsafe.Pointer(&owner))); errno != 0 {
				return fmt.Errorf("can't be checked: get owner of user namespace: %w", errno)
			}
			if int(owner) != uid {
				return fmt.Errorf("is owned by uid %d, not %d", owner, uid)
			}
			return nil
		}
		unix.Close(fd)
		fd = parent
	}
	return fmt.Errorf("is nested deeper than the kernel allows")
}

// Whether fd is the namespace st describes
func same(fd int, st unix.Stat_t) bool {
	var fst unix.Stat_t
	return unix.Fstat(fd, &fst) == nil && fst.Dev == st.Dev && fst.Ino == st.Ino
}

// Index of the device carrying the main table's default route with the lowest metric, IPv4 first
func defaultRouteLink() (int, error) {
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_DST)
		if err != nil {
			return -1, fmt.Errorf("List default routes: %w", err)
		}
		if link := lowestMetric(routes); link != -1 {
			return link, nil
		}
	}
	return -1, fmt.Errorf("No default route")
}

// Device index of the route with the lowest metric, skipping routes without a device; -1 if none
func lowestMetric(routes []netlink.Route) int {
	best := -1
	for i, r := range routes {
		if r.LinkIndex > 0 && (best == -1 || r.Priority < routes[best].Priority) {
			best = i
		}
	}
	if best == -1 {
		return -1
	}
	return routes[best].LinkIndex
}

// Locally administered unicast MAC, stable per machine, uid and name so DHCP keeps handing out the same lease. The
// empty name hashes as before names existed, which keeps the default launcher's lease
func stableMAC(machineID []byte, uid int, name string) net.HardwareAddr {
	in := fmt.Appendf(nil, "netns-macvlan\x00%s\x00%d", machineID, uid)
	if name != "" {
		in = fmt.Appendf(in, "\x00%s", name)
	}
	sum := sha256.Sum256(in)
	mac := net.HardwareAddr(sum[:6])
	mac[0] = mac[0]&^0x01 | 0x02
	return mac
}
