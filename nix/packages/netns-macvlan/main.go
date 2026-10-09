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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const usage = `netns-macvlan - Give a user-owned network namespace its own macvlan on the LAN

Usage:
  netns-macvlan <pid>

Creates eth0 in the network namespace of <pid>: a macvlan in private mode on
the device carrying the default route, with a MAC derived from the machine ID
and the caller's uid. <pid> must belong to the caller, and its network
namespace must be owned by a user namespace the caller owns.
`

func main() {
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
	if err := run(pid); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run(pid int) error {
	uid := unix.Getuid()
	netnsFd, err := openNetns(pid, uid)
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
	mac := stableMAC(machineID, uid)
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

// Opens the network namespace of pid after checking that the caller may hand it a LAN interface
func openNetns(pid, uid int) (int, error) {
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
	var owner uint32
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(usernsFd), unix.NS_GET_OWNER_UID, uintptr(unsafe.Pointer(&owner))); errno != 0 {
		return -1, fmt.Errorf("Get owner of user namespace: %w", errno)
	}
	if int(owner) != uid {
		return -1, fmt.Errorf("Network namespace of %d is owned by uid %d, not %d", pid, owner, uid)
	}
	ok = true
	return netnsFd, nil
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

// Locally administered unicast MAC, stable per machine and uid so DHCP keeps handing out the same lease
func stableMAC(machineID []byte, uid int) net.HardwareAddr {
	sum := sha256.Sum256(fmt.Appendf(nil, "netns-macvlan\x00%s\x00%d", machineID, uid))
	mac := net.HardwareAddr(sum[:6])
	mac[0] = mac[0]&^0x01 | 0x02
	return mac
}
