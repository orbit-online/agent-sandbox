package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/docopt/docopt-go"
	"golang.org/x/sys/unix"
)

const usage = `dbus-proxy - Filter a sandbox's D-Bus traffic, taking xdg-dbus-proxy's arguments

Usage:
  dbus-proxy [--fd=<fd>] <address> <path> [--filter] [--see=<name>]... [--talk=<name>]... [--own=<name>]... [--call=<rule>]... [--broadcast=<rule>]...
  dbus-proxy --help

Listens on <path> and connects each client to the bus at <address>. The subset
of xdg-dbus-proxy's arguments nixpak passes, with their meaning:

  --fd=<fd>             Write a byte to <fd> once listening, exit when it closes
  --filter              Apply the rules below; without it every message passes
  --see=<name>          Let the client see <name>
  --talk=<name>         Let the client call and signal <name>
  --own=<name>          Let the client own <name>
  --call=<rule>         NAME=[METHOD][@PATH]: calls the client may make to NAME
  --broadcast=<rule>    NAME=[METHOD][@PATH]: broadcasts it gets from NAME

A name may end in ".*" for the names below it, a path in "/*" for its subtree.
With or without --filter, the client can't monitor the bus or eavesdrop.
`

// Listens for clients of one bus and applies one set of rules
type Proxy struct {
	bus    []*net.UnixAddr
	rules  *Rules
	filter bool
	log    *slog.Logger

	mu      sync.Mutex
	clients int
}

// Clients connected at once; the app opens a handful
const maxClients = 256

func NewProxy(address string, rules *Rules, filter bool) (*Proxy, error) {
	addrs, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	return &Proxy{bus: addrs, rules: rules, filter: filter, log: slog.Default()}, nil
}

// Accepts clients until the listener closes
func (p *Proxy) Serve(l *net.UnixListener) error {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		p.mu.Lock()
		full := p.clients >= maxClients
		if !full {
			p.clients++
		}
		p.mu.Unlock()
		if full {
			p.log.Warn("Client refused: too many clients")
			conn.Close()
			continue
		}
		go func() {
			defer func() {
				p.mu.Lock()
				p.clients--
				p.mu.Unlock()
			}()
			p.handle(conn)
		}()
	}
}

// The rules from the command line
func parseRules(opts docopt.Opts) (*RuleSet, error) {
	rs := NewRuleSet()
	for _, o := range []struct {
		flag string
		add  func(string) error
	}{
		{"--see", func(a string) error { return rs.AddPolicy(a, policySee) }},
		{"--talk", func(a string) error { return rs.AddPolicy(a, policyTalk) }},
		{"--own", func(a string) error { return rs.AddPolicy(a, policyOwn) }},
		{"--call", func(a string) error { return rs.AddRule(a, filterCall) }},
		{"--broadcast", func(a string) error { return rs.AddRule(a, filterBroadcast) }},
	} {
		args, _ := opts[o.flag].([]string)
		for _, a := range args {
			if err := o.add(a); err != nil {
				return nil, fmt.Errorf("%s: %w", o.flag, err)
			}
		}
	}
	return rs, nil
}

// Listens at path, replacing what's there, as xdg-dbus-proxy does
func listen(path string) (*net.UnixListener, error) {
	os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("Listen on %s: %w", path, err)
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// Tells the launcher the proxy is ready, then waits for it to close its end
func syncFD(fd int) error {
	if _, err := unix.Write(fd, []byte("x")); err != nil {
		return fmt.Errorf("Write to --fd %d: %w", fd, err)
	}
	for {
		// No events asked for: poll returns on POLLHUP or POLLERR alone, which a pipe's write end gets when the
		// read end closes
		fds := []unix.PollFd{{Fd: int32(fd)}}
		_, err := unix.Poll(fds, -1)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return err
		}
		if fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return nil
		}
	}
}

func run(opts docopt.Opts) error {
	rs, err := parseRules(opts)
	if err != nil {
		return err
	}
	address, _ := opts.String("<address>")
	path, _ := opts.String("<path>")
	filter, _ := opts.Bool("--filter")
	p, err := NewProxy(address, NewRules(rs), filter)
	if err != nil {
		return err
	}
	l, err := listen(path)
	if err != nil {
		return err
	}
	defer l.Close()
	served := make(chan error, 1)
	go func() { served <- p.Serve(l) }()
	if s, ok := opts["--fd"].(string); ok {
		fd, err := strconv.Atoi(s)
		if err != nil || fd < 0 {
			return fmt.Errorf("Invalid --fd %q", s)
		}
		go func() { served <- syncFD(fd) }()
	}
	return <-served
}

func main() {
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
