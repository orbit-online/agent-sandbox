package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"golang.org/x/sys/unix"
)

const usage = `dbus-proxy - Filter a sandbox's D-Bus traffic, taking xdg-dbus-proxy's arguments

Usage:
  dbus-proxy [--fd=<fd>] <address> <path> --filter [--see=<name>]... [--talk=<name>]... [--own=<name>]... [--call=<rule>]... [--broadcast=<rule>]...
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
`

// The rules from the command line
func parseRules(opts docopt.Opts) (*rules.Set, error) {
	arg := func(flag string) []string { a, _ := opts[flag].([]string); return a }
	return rules.Parse(rules.Args{See: arg("--see"), Talk: arg("--talk"), Own: arg("--own"), Call: arg("--call"),
		Broadcast: arg("--broadcast")})
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
