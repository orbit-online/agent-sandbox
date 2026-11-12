package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/internal/journal"
	"golang.org/x/sys/unix"
)

const usage = `dbus-proxy - Filter a sandbox's D-Bus traffic by static rules, started as xdg-dbus-proxy

Usage:
  dbus-proxy [--fd=<fd>] <address> <path> --config=<file> --filter
  dbus-proxy --help

Listens on <path> and connects each client to the bus at <address>, passing what the rules let through:

  --fd=<fd>          Write a byte to <fd> once listening, exit when it closes
  --config=<file>    The rules, JSON with an entry per well-known name:
                       {"<name>": {"policy": "see"|"talk"|"own", "call": [RULE], "broadcast": [RULE]}}
                     a policy, rules or both. RULE is [METHOD][@PATH]: METHOD "*", "IFACE.*" or
                     "IFACE.MEMBER", PATH an object path, ending in "/*" for its subtree too
  --filter           Required, as nixpak always passes it

Names are exact; any rule makes its name visible. Broadcasts pass by broadcast rule, or all of a name with talk or
own. The client can't monitor the bus or eavesdrop, whatever the rules (docs/permissions.md, D-Bus).
`

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
	file, _ := opts.String("--config")
	rs, err := rules.Load(file)
	if err != nil {
		return err
	}
	address, _ := opts.String("<address>")
	path, _ := opts.String("<path>")
	p, err := NewProxy(address, rules.New(rs))
	if err != nil {
		return err
	}
	served := make(chan error, 2)
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
