package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mcpserver"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"github.com/orbit-online/agent-sandbox/internal/journal"
)

const usage = `permissions-broker - Grant a sandbox outside access while it runs

Usage:
  permissions-broker serve <config>
  permissions-broker cleanup <config>
  permissions-broker mcp [--commands=<file>] [<socket>]
  permissions-broker share [<socket>]
  permissions-broker make-shared <dir> <dirid>
  permissions-broker clone-tree <root> <rel> <mode>
  permissions-broker move-tree <dir> <dirid> <name>
  permissions-broker detach <dir> <dirid> <entry>...

serve runs the daemon for one launcher, as described in docs/permissions.md:
it finds the launcher's running sandbox by app ID, listens on request.sock in
the grant directory for the sandbox and on control.sock for the Permissions
window, asks the user about each request with a notification, and ends grants
on their lease. Exits when the sandbox does. <config> is the JSON the module
writes: appId, launcher, grantDir, controlSocket, sandboxGrantDir,
window (the command opening the Permissions window), folders (the folders
that may be granted, each a path and rw), commands (the host command
capabilities), sockets (the host socket capabilities), grants (the standing
grants, each a capability and its parameters, granted at start without
asking) and overview
(what the sandbox reaches from its start, which control.sock's state passes
on to the window as is). Environment variables in the paths and the window
command are expanded.

cleanup ends the grants of a daemon that stopped, as its unit's ExecStopPost:
call units stopped, folder grants detached. A daemon that starts does it too.

mcp is the MCP server inside the sandbox, a client of <socket>
(/run/permissions/request.sock by default). --commands names the host
commands' declarations, which it offers as tools.

Options:
  --commands=<file>  The host commands, as the config's commands without run.

share asks the daemon to make the grant directory a shared mount, from the
sandbox's outer mount namespace before the FHS env's bwrap copies it. Waits up
to 10 s for <socket> (/run/permissions/request.sock by default) to appear.

make-shared, clone-tree, move-tree and detach are the daemon's
helpers for attach grants, run through nsenter in the sandbox's namespaces (see
internal/mounts). <dir> is the grant directory where the sandbox sees it,
<dirid> the device and inode it must have there.
`

// From PATH: the package's wrapper puts util-linux first and the host system's profile, with its systemd, last.
// Variables so tests can put fakes in their place
var (
	systemdRun = "systemd-run"
	systemctl  = "systemctl"
)

func main() {
	journal.Setup()
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		slog.Error("Parse arguments", "err", err)
		os.Exit(2)
	}
	switch {
	case opts["serve"] == true:
		err = serve(opts["<config>"].(string))
	case opts["cleanup"] == true:
		var cfg config
		if cfg, err = readConfig(opts["<config>"].(string)); err == nil {
			sb, _ := lookupSandbox(os.Getenv("XDG_RUNTIME_DIR"), cfg.AppID)
			cleanup(cfg, sb, realClock{})
		}
	case opts["mcp"] == true:
		commands, _ := opts.String("--commands")
		err = mcpserver.Run(socketArg(opts), commands)
	case opts["share"] == true:
		err = share(socketArg(opts))
	case opts["make-shared"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		err = mounts.MakeShared(dir, id)
	case opts["clone-tree"] == true:
		root, _ := opts.String("<root>")
		rel, _ := opts.String("<rel>")
		mode, _ := opts.String("<mode>")
		err = mounts.CloneTree(root, rel, mode)
	case opts["move-tree"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		name, _ := opts.String("<name>")
		err = mounts.MoveTree(dir, id, name)
	case opts["detach"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		names, _ := opts["<entry>"].([]string)
		err = mounts.DetachHelper(dir, id, names)
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func socketArg(opts docopt.Opts) string {
	if socket, _ := opts.String("<socket>"); socket != "" {
		return socket
	}
	return "/run/permissions/request.sock"
}

func share(socket string) error {
	for range 50 {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_, err := callBroker(socket, wire.Request{Op: "share"})
	return err
}

// callBroker sends one request to the broker at socket and reads its answer
func callBroker(socket string, req wire.Request) (response, error) {
	var res response
	if err := wire.Call(socket, req, &res); err != nil {
		return response{}, err
	}
	return res, nil
}
