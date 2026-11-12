package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// DNS of the sandbox: the nameservers option when set, or else what systemd-resolved on the host, or NetworkManager
// without it, configures for the uplinks the sandbox leaves through (resolvconf.go), followed on the system bus and
// netlink while the app runs. Read access to both is unprivileged. The file is written in place through
// claude-desktop-state

const (
	resolvedName  = "org.freedesktop.resolve1"
	resolvedPath  = "/org/freedesktop/resolve1"
	resolvedIface = "org.freedesktop.resolve1.Manager"
	nmName        = "org.freedesktop.NetworkManager"
	nmPath        = "/org/freedesktop/NetworkManager/DnsManager"
	nmIface       = "org.freedesktop.NetworkManager.DnsManager"
	// How long after a change the file follows: routes and updates of NetworkManager come in bursts, and sandbox-uplink
	// publishes the uplinks every half second
	dnsSettle = time.Second
)

type dns struct {
	cfg  *config
	bus  *dbus.Conn // The system bus, nil without one
	mu   sync.Mutex
	last *string // What the file holds
}

// newDNS connects to the system bus unless the nameservers option is set or the sandbox has no network
func newDNS(cfg *config) *dns {
	d := &dns{cfg: cfg}
	if cfg.Network && len(cfg.Nameservers) == 0 {
		bus, err := dbus.ConnectSystemBus()
		if err != nil {
			slog.Warn("No system bus for the DNS of the host", "err", err)
		}
		d.bus = bus
	}
	return d
}

// update writes the resolv.conf of the sandbox when what it should hold changed
func (d *dns) update() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, source := d.read()
	if d.last != nil && *d.last == conf {
		return nil
	}
	cmd := exec.Command(d.cfg.State, d.cfg.Home, "--", "resolv")
	cmd.Stdin = strings.NewReader(conf)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Write the resolv.conf of the sandbox: %w: %s", err, out)
	}
	d.last = &conf
	if conf == "" && d.cfg.Network {
		slog.Warn("No DNS in the sandbox: no nameservers option, and the DNS of the host has no server the sandbox reaches",
			"source", source)
	} else if conf != "" {
		slog.Info("DNS of the sandbox", "source", source, "resolv.conf", conf)
	}
	return nil
}

// read returns the resolv.conf the sandbox gets and where it came from
func (d *dns) read() (string, string) {
	if !d.cfg.Network {
		return "", "no network"
	}
	if len(d.cfg.Nameservers) > 0 {
		var b strings.Builder
		for _, ns := range d.cfg.Nameservers {
			b.WriteString("nameserver " + ns + "\n")
		}
		return b.String(), "nameservers option"
	}
	if d.bus == nil {
		return "", "none"
	}
	c, source, err := d.hostConfig()
	if err != nil {
		slog.Warn("Read the DNS of the host", "err", err)
		return "", "none"
	}
	ups, err := d.uplinks()
	if err != nil {
		slog.Warn("Find the uplinks", "err", err)
	}
	return resolvConf(c, ups, route), source
}

// hostConfig reads the DNS configuration of resolved, or of NetworkManager when resolved doesn't run, never starting either
func (d *dns) hostConfig() (dnsConfig, string, error) {
	var servers []resolvedServer
	err := d.get(resolvedName, resolvedPath, resolvedIface, "DNSEx", &servers)
	if err == nil {
		var domains []resolvedDomain
		if err := d.get(resolvedName, resolvedPath, resolvedIface, "Domains", &domains); err != nil {
			return dnsConfig{}, "", err
		}
		return fromResolved(servers, domains), "systemd-resolved", nil
	}
	if !absent(err) {
		return dnsConfig{}, "", err
	}
	var entries []map[string]dbus.Variant
	err = d.get(nmName, nmPath, nmIface, "Configuration", &entries)
	if err == nil {
		return fromNM(entries, ifindex), "NetworkManager", nil
	}
	if !absent(err) {
		return dnsConfig{}, "", err
	}
	return dnsConfig{}, "none", nil
}

func (d *dns) get(name, path, iface, prop string, v any) error {
	var variant dbus.Variant
	err := d.bus.Object(name, dbus.ObjectPath(path)).Call("org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart,
		iface, prop).Store(&variant)
	if err != nil {
		return err
	}
	if err := dbus.Store([]any{variant.Value()}, v); err != nil {
		return fmt.Errorf("Read %s of %s: %w", prop, name, err)
	}
	return nil
}

// absent is whether err says the service isn't there
func absent(err error) bool {
	var e dbus.Error
	return errors.As(err, &e) && (e.Name == "org.freedesktop.DBus.Error.ServiceUnknown" ||
		e.Name == "org.freedesktop.DBus.Error.NameHasNoOwner")
}

// uplinks asks netns-netkit for the uplinks with the default routes, which only its group reads
func (d *dns) uplinks() (map[int]bool, error) {
	out, err := exec.Command(filepath.Join(d.cfg.Tools.WrapperDir, "netns-netkit"), "uplinks").Output()
	if err != nil {
		return nil, fmt.Errorf("Run netns-netkit uplinks: %w", err)
	}
	ups := map[int]bool{}
	for _, f := range strings.Fields(string(out)) {
		var i int
		if _, err := fmt.Sscan(f, &i); err == nil && i != 0 {
			ups[i] = true
		}
	}
	return ups, nil
}

func ifindex(name string) int {
	if iface, err := net.InterfaceByName(name); err == nil {
		return iface.Index
	}
	return 0
}

// route asks the routing of the host for a
func route(a netip.Addr) (int, bool, error) {
	rs, err := netlink.RouteGet(a.AsSlice())
	if err != nil || len(rs) == 0 {
		return 0, false, fmt.Errorf("Route to %s: %w", a, err)
	}
	return rs[0].LinkIndex, rs[0].Type == unix.RTN_LOCAL, nil
}

// follow updates the file on every change of the DNS configuration or routes of the host, until the process ends
func (d *dns) follow() {
	if d.bus == nil {
		return
	}
	changes := make(chan struct{}, 1)
	poke := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	signals := make(chan *dbus.Signal, 16)
	d.bus.Signal(signals)
	for _, m := range [][]dbus.MatchOption{
		{dbus.WithMatchObjectPath(resolvedPath), dbus.WithMatchInterface("org.freedesktop.DBus.Properties")},
		{dbus.WithMatchObjectPath(nmPath), dbus.WithMatchInterface("org.freedesktop.DBus.Properties")},
		// Either starting or ending
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
			dbus.WithMatchArg(0, resolvedName)},
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
			dbus.WithMatchArg(0, nmName)},
	} {
		if err := d.bus.AddMatchSignal(m...); err != nil {
			slog.Warn("Follow the DNS of the host", "err", err)
		}
	}
	go func() {
		for range signals {
			poke()
		}
	}()
	routes := make(chan netlink.RouteUpdate, 64)
	if err := netlink.RouteSubscribe(routes, nil); err != nil {
		slog.Warn("Follow the routes of the host", "err", err)
	} else {
		go func() {
			for range routes {
				poke()
			}
		}()
	}
	go func() {
		for range changes {
			time.Sleep(dnsSettle)
			// What came meanwhile is covered
			select {
			case <-changes:
			default:
			}
			if err := d.update(); err != nil {
				slog.Warn("DNS", "err", err)
			}
		}
	}()
}
