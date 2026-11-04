package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/control"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"github.com/orbit-online/agent-sandbox/internal/dbuspolicy"
	"golang.org/x/sys/unix"
)

const usage = `dbus-proxy - Filter a sandbox's D-Bus traffic, taking xdg-dbus-proxy's arguments

Usage:
  dbus-proxy [--fd=<fd>] [--control=<path> --bus=<bus> [--app-id=<id>]] [--pid=<pid>] <address> <path> --filter [--see=<name>]... [--talk=<name>]... [--own=<name>]... [--call=<rule>]... [--broadcast=<rule>]...
  dbus-proxy --help

Listens on <path> and connects each client to the bus at <address>. The subset
of xdg-dbus-proxy's arguments nixpak passes, with their meaning:

  --fd=<fd>             Write a byte to <fd> once listening, exit when it closes
  --filter              Apply the rules below; required, as nixpak always passes it
  --see=<name>          Let the client see <name>
  --talk=<name>         Let the client call and signal <name>
  --own=<name>          Let the client own <name>
  --call=<rule>         NAME=[METHOD][@PATH]: calls the client may make to NAME
  --broadcast=<rule>    NAME=[METHOD][@PATH]: broadcasts it gets from NAME

Names are exact (xdg-dbus-proxy's ".*" wildcards aren't taken); a path may end
in "/*" for its subtree.
The client can't monitor the bus or eavesdrop, whatever the rules.

  --control=<path>      Take live rule sets from the permissions broker on a
                        socket at <path>, relative to $XDG_RUNTIME_DIR (mode
                        0600, its directory made 0700); see control.go
  --bus=<bus>           session or system: the policy live sets are checked
                        against (internal/dbuspolicy)
  --app-id=<id>         The sandbox's app ID, which live sets may own names
                        below (none without it)
  --pid=<pid>           Exit when process <pid> does
`

// Listens for clients of one bus and applies one set of rules
type Proxy struct {
	bus    []*net.UnixAddr
	reg    *control.Registry // The rules in force and the clients past authentication
	log    *slog.Logger
	budget *wire.Budget
	uid    int // The uid a client and the broker must have

	mu      sync.Mutex
	clients int
}

// Clients connected at once; the app opens a handful
const maxClients = 256

func NewProxy(address string, rules *rules.Rules) (*Proxy, error) {
	addrs, err := parseAddress(address)
	if err != nil {
		return nil, err
	}
	return &Proxy{bus: addrs, reg: control.NewRegistry(rules), log: slog.Default(), budget: wire.NewBudget(),
		uid: os.Getuid()}, nil
}

// The control socket's server, for live sets checked against bus's policy and the sandbox's app ID
func (p *Proxy) control(bus, appID string) *control.Server {
	return &control.Server{Registry: p.reg, Bus: bus, AppID: appID, UID: p.uid, Log: p.log}
}

// Accepts clients until the listener closes. Out of file descriptors or memory, it waits and tries again, as
// net/http does: clients ending free them
func (p *Proxy) Serve(l *net.UnixListener) error {
	var backoff time.Duration
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) || errors.Is(err, unix.ENOBUFS) ||
				errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.ECONNABORTED) {
				backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
				p.log.Warn("Accept failed, trying again", "err", err, "in", backoff)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		backoff = 0
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
func parseRules(opts docopt.Opts) (*rules.Set, error) {
	arg := func(flag string) []string { a, _ := opts[flag].([]string); return a }
	return rules.Parse(rules.Args{See: arg("--see"), Talk: arg("--talk"), Own: arg("--own"), Call: arg("--call"),
		Broadcast: arg("--broadcast")})
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

// Listens on the control socket at rel beneath $XDG_RUNTIME_DIR, as nixpak passes dbus.args unexpanded: a clean
// relative path, its directory made 0700 and the socket bound under umask 077, then made 0600, the mode the doc names
func listenControl(rel string) (*net.UnixListener, error) {
	run := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(run) {
		return nil, errors.New("--control needs $XDG_RUNTIME_DIR")
	}
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("--control %q: a clean path relative to $XDG_RUNTIME_DIR", rel)
	}
	path := filepath.Join(run, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	old := unix.Umask(0o077)
	l, err := listen(path)
	unix.Umask(old)
	if err != nil {
		return nil, err
	}
	// Bound 0700; connecting takes write permission only
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Waits for the process behind pidfd to end
func waitPidfd(pidfd int) error {
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(fds, -1); err == nil || !errors.Is(err, unix.EINTR) {
			return err
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
	p, err := NewProxy(address, rules.New(rs))
	if err != nil {
		return err
	}
	served := make(chan error, 4)
	if s, ok := opts["--pid"].(string); ok {
		// Taken before listening: whoever waits for the socket knows the pid was watched while it lived
		pid, err := strconv.Atoi(s)
		if err != nil || pid <= 0 {
			return fmt.Errorf("Invalid --pid %q", s)
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			return fmt.Errorf("Watch --pid %d: %w", pid, err)
		}
		go func() { served <- waitPidfd(pidfd) }()
	}
	if rel, ok := opts["--control"].(string); ok {
		bus, _ := opts.String("--bus")
		appID, _ := opts.String("--app-id")
		if _, ok := dbuspolicy.Buses[bus]; !ok {
			return fmt.Errorf("Invalid --bus %q: session or system", bus)
		}
		cl, err := listenControl(rel)
		if err != nil {
			return err
		}
		defer cl.Close()
		go func() { served <- p.control(bus, appID).Serve(cl) }()
	}
	l, err := listen(path)
	if err != nil {
		return err
	}
	defer l.Close()
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
