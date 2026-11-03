package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mcpserver"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/notify"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"golang.org/x/sys/unix"
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
tree.go and helpers.go). <dir> is the grant directory where the sandbox sees it,
<dirid> the device and inode it must have there.
`

// From PATH: the package's wrapper puts util-linux first and the host system's profile, with its systemd, last.
// Variables so tests can put fakes in their place
var (
	nsenter    = "nsenter"
	systemdRun = "systemd-run"
	systemctl  = "systemctl"
)

func main() {
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
			cleanup(cfg, sb)
		}
	case opts["mcp"] == true:
		commands, _ := opts.String("--commands")
		err = mcpserver.Run(socketArg(opts), commands)
	case opts["share"] == true:
		err = share(socketArg(opts))
	case opts["make-shared"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		err = makeShared(dir, id)
	case opts["clone-tree"] == true:
		root, _ := opts.String("<root>")
		rel, _ := opts.String("<rel>")
		mode, _ := opts.String("<mode>")
		err = cloneTree(root, rel, mode)
	case opts["move-tree"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		name, _ := opts.String("<name>")
		err = moveTree(dir, id, name)
	case opts["detach"] == true:
		dir, _ := opts.String("<dir>")
		id, _ := opts.String("<dirid>")
		names, _ := opts["<entry>"].([]string)
		err = detachHelper(dir, id, names)
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

type config struct {
	AppID         string `json:"appId"`
	Launcher      string `json:"launcher"`
	GrantDir      string `json:"grantDir"`
	ControlSocket string `json:"controlSocket"`
	// The daemon's systemd unit, which call units are bound to
	Unit            string   `json:"unit"`
	SandboxGrantDir string   `json:"sandboxGrantDir"`
	Window          []string `json:"window"`
	// Never granted as an attach source, whatever a ceiling says: every launcher's state directory and runtime
	// directory
	Denied []string `json:"denied"`
	// What the folders capability may grant
	Folders []source `json:"folders"`
	// Host command and host socket capabilities
	Commands []commandConfig  `json:"commands"`
	Sockets  []socketConfig   `json:"sockets"`
	DBus     []dbusConfig     `json:"dbus"`
	Grants   []standingConfig `json:"grants"`
	// Each bus's proxy's control socket, by bus: session, system
	DBusControl map[string]string `json:"dbusControl,omitempty"`
	// The launcher's static access (binds, devices, D-Bus rules, the network, what the module adds), for the window
	Overview json.RawMessage `json:"overview,omitempty"`
}

func readConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("Read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("Parse config %s: %w", path, err)
	}
	for _, p := range []*string{&cfg.GrantDir, &cfg.ControlSocket} {
		*p = os.ExpandEnv(*p)
	}
	for bus, p := range cfg.DBusControl {
		cfg.DBusControl[bus] = os.ExpandEnv(p)
	}
	for i := range cfg.Window {
		cfg.Window[i] = os.ExpandEnv(cfg.Window[i])
	}
	for i := range cfg.Denied {
		cfg.Denied[i] = os.ExpandEnv(cfg.Denied[i])
	}
	if cfg.Denied, err = checkDenied(cfg.Denied); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func serve(path string) error {
	cfg, err := readConfig(path)
	if err != nil {
		return err
	}
	caps, err := loadCapabilities(cfg)
	if err != nil {
		return err
	}
	unix.Umask(0o077)
	sb, err := findSandbox(cfg.AppID)
	if err != nil {
		return err
	}
	b, err := newBroker(cfg, caps, sb, notify.Ask)
	if err != nil {
		return err
	}
	watchLogind(b, logindSignals)
	return b.run()
}

// loadCapabilities makes the config's capabilities: folders, host commands, host sockets and D-Bus rule sets
func loadCapabilities(cfg config) (map[string]*capability, error) {
	caps := map[string]*capability{}
	folders, err := foldersCap(cfg.Folders)
	if err != nil {
		return nil, err
	}
	if folders != nil {
		caps[folders.id()] = folders
	}
	if err := loadCommands(cfg.Commands, caps); err != nil {
		return nil, err
	}
	if err := loadSockets(cfg.Sockets, caps); err != nil {
		return nil, err
	}
	if err := loadDBus(cfg.DBus, caps, cfg.AppID); err != nil {
		return nil, err
	}
	return caps, nil
}
