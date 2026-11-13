package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/sandbox"
)

// DNS of the sandbox: the nameservers option when set, or else what systemd-resolved on the host, or NetworkManager
// without it, configures for the uplinks the sandbox leaves through (resolvconf.go), followed on the system bus and
// netlink while the app runs, and with the routes of the host its default routes (sandboxRoutes). Read access to both
// is unprivileged. The file is written in place through claude-desktop-state

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
	// How long after a failed read of the DNS of the host it's read again
	dnsRetry = 5 * time.Second
	// How often follow looks for the sandbox until it runs
	sandboxPoll = 500 * time.Millisecond
)

type dns struct {
	cfg  *config
	bus  *dbus.Conn // The system bus, nil without one
	mu   sync.Mutex
	last *string // What the file holds
	// The routing of the host, which tests fake
	route hostRoute
}

// newDNS connects to the system bus unless the nameservers option is set or the sandbox has no network
func newDNS(cfg *config) *dns {
	d := &dns{cfg: cfg, route: route}
	if cfg.Network && len(cfg.Nameservers) == 0 {
		bus, err := dbus.ConnectSystemBus()
		if err != nil {
			slog.Warn("No system bus for the DNS of the host", "err", err)
		}
		d.bus = bus
	}
	return d
}

// errUnread is the DNS of the host failing to be read: the file keeps what it holds, and follow tries again
var errUnread = errors.New("Read the DNS of the host")

// update writes the resolv.conf of the sandbox when what it should hold changed
func (d *dns) update() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	conf, source, err := d.read()
	if err != nil {
		return fmt.Errorf("%w, keeping the resolv.conf of the sandbox: %w", errUnread, err)
	}
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

// read returns the resolv.conf the sandbox gets and where it came from, under d.mu. A service of the host that isn't
// there is no DNS from it; any other error reading it is an error
func (d *dns) read() (string, string, error) {
	if !d.cfg.Network {
		return "", "no network", nil
	}
	if len(d.cfg.Nameservers) > 0 {
		var b strings.Builder
		for _, ns := range d.cfg.Nameservers {
			b.WriteString("nameserver " + ns + "\n")
		}
		return b.String(), "nameservers option", nil
	}
	if d.bus == nil {
		return "", "none", nil
	}
	c, source, err := d.hostConfig()
	if err != nil {
		return "", "", err
	}
	ups, err := d.uplinks()
	if err != nil {
		return "", "", err
	}
	return resolvConf(c, ups, d.route), source, nil
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
		defaultRoute := map[int]bool{}
		for _, s := range servers {
			if _, done := defaultRoute[int(s.Ifindex)]; s.Ifindex == 0 || done {
				continue
			}
			dr, ok, err := d.linkDefaultRoute(s.Ifindex)
			if err != nil {
				return dnsConfig{}, "", err
			}
			if ok {
				defaultRoute[int(s.Ifindex)] = dr
			}
		}
		return fromResolved(servers, domains, defaultRoute), "systemd-resolved", nil
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

// linkDefaultRoute reads DefaultRoute of a link of resolved; false for ok when resolved doesn't know the link (gone
// meanwhile)
func (d *dns) linkDefaultRoute(ifindex int32) (defaultRoute, ok bool, err error) {
	var path dbus.ObjectPath
	err = d.bus.Object(resolvedName, resolvedPath).Call(resolvedIface+".GetLink", dbus.FlagNoAutoStart, ifindex).Store(&path)
	var de dbus.Error
	if errors.As(err, &de) && de.Name == "org.freedesktop.resolve1.NoSuchLink" {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if err := d.get(resolvedName, string(path), "org.freedesktop.resolve1.Link", "DefaultRoute", &defaultRoute); err != nil {
		return false, false, err
	}
	return defaultRoute, true, nil
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

// uplinks are the uplinks with the default routes
func (d *dns) uplinks() (map[int]bool, error) {
	ifs, err := defaultUplinks(d.netnsNetkit())
	if err != nil {
		return nil, err
	}
	ups := map[int]bool{}
	for _, i := range ifs {
		if i != 0 {
			ups[i] = true
		}
	}
	return ups, nil
}

func (d *dns) netnsNetkit() string {
	return filepath.Join(d.cfg.Tools.WrapperDir, "netns-netkit")
}

// syncRoutes keeps the default routes of the running sandbox to the families the host has an uplink for
// (sandboxRoutes). No sandbox yet: the bwrap helper routes it as it sets it up
func (d *dns) syncRoutes() {
	pid, fd, err := sandbox.Find(os.Getenv("XDG_RUNTIME_DIR"), d.cfg.AppID)
	if err != nil {
		slog.Debug("No sandbox to route", "err", err)
		return
	}
	defer unix.Close(fd)
	ns, err := openNs(pid, fd)
	if err == nil {
		defer closeNs(ns)
		err = sandboxRoutes(d.netnsNetkit(), d.cfg.Tools.Nsenter, d.cfg.Tools.IP, ns)
	}
	if err != nil {
		slog.Warn("Default routes of the sandbox", "err", err)
	}
}

// pokeWhenUp pokes once the sandbox shows up: the bwrap helper routes it before nixpak writes bwrapinfo.json, which
// sandbox.Find needs, so a change of the routes of the host in between would otherwise wait for the next one
func (d *dns) pokeWhenUp(poke func()) {
	for {
		if _, fd, err := sandbox.Find(os.Getenv("XDG_RUNTIME_DIR"), d.cfg.AppID); err == nil {
			unix.Close(fd)
			poke()
			return
		}
		time.Sleep(sandboxPoll)
	}
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

// follow updates the file and the default routes of the sandbox (syncRoutes) on every change of the DNS configuration or
// routes of the host, until the process ends, and once right after it subscribed: what changed while the sandbox
// started is covered. A read that fails is tried again after dnsRetry; the system bus and the route subscription are
// subscribed to again when they close
func (d *dns) follow() {
	if !d.cfg.Network {
		return
	}
	changes := make(chan struct{}, 1)
	poke := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	if d.bus != nil {
		d.followBus(poke)
	}
	d.followRoutes(poke)
	go d.pokeWhenUp(poke)
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
				if errors.Is(err, errUnread) {
					time.AfterFunc(dnsRetry, poke)
				}
			}
			d.syncRoutes()
		}
	}()
	poke()
}

// followBus pokes on the changes of resolved and NetworkManager on the system bus, connecting again when it closes
func (d *dns) followBus(poke func()) {
	signals := d.subscribe(d.bus)
	go func() {
		for {
			for range signals {
				poke()
			}
			// godbus closes the channel when the connection closes
			slog.Warn("Lost the system bus, following the DNS of the host again once it's back")
			var bus *dbus.Conn
			for wait := time.Second; ; wait = min(2*wait, time.Minute) {
				time.Sleep(wait)
				var err error
				if bus, err = dbus.ConnectSystemBus(); err == nil {
					break
				}
			}
			d.mu.Lock()
			d.bus = bus
			d.mu.Unlock()
			signals = d.subscribe(bus)
			slog.Info("Following the DNS of the host again")
			poke()
		}
	}()
}

// followRoutes pokes on the route events of the host, subscribing again when the subscription closes
func (d *dns) followRoutes(poke func()) {
	routes, err := d.routes()
	go func() {
		for wait := time.Second; ; wait = min(2*wait, time.Minute) {
			if err == nil {
				for range routes {
					poke()
				}
				slog.Warn("Lost the routes of the host, subscribing again")
			} else {
				slog.Warn("Follow the routes of the host", "err", err)
			}
			time.Sleep(wait)
			if routes, err = d.routes(); err == nil {
				poke()
			}
		}
	}()
}

// subscribe asks bus for the changes of resolved and NetworkManager, and returns where they arrive
func (d *dns) subscribe(bus *dbus.Conn) chan *dbus.Signal {
	signals := make(chan *dbus.Signal, 16)
	bus.Signal(signals)
	for _, m := range [][]dbus.MatchOption{
		{dbus.WithMatchObjectPath(resolvedPath), dbus.WithMatchInterface("org.freedesktop.DBus.Properties")},
		{dbus.WithMatchObjectPath(nmPath), dbus.WithMatchInterface("org.freedesktop.DBus.Properties")},
		// Either starting or ending
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
			dbus.WithMatchArg(0, resolvedName)},
		{dbus.WithMatchSender("org.freedesktop.DBus"), dbus.WithMatchMember("NameOwnerChanged"),
			dbus.WithMatchArg(0, nmName)},
	} {
		if err := bus.AddMatchSignal(m...); err != nil {
			slog.Warn("Follow the DNS of the host", "err", err)
		}
	}
	return signals
}

// routes subscribes to the routes of the host. The channel closes on an error, ENOBUFS among them when the updates came
// faster than they were read
func (d *dns) routes() (chan netlink.RouteUpdate, error) {
	routes := make(chan netlink.RouteUpdate, 64)
	err := netlink.RouteSubscribeWithOptions(routes, nil, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) { slog.Warn("Follow the routes of the host", "err", err) },
	})
	return routes, err
}
