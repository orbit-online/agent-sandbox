package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/docopt/docopt-go"
	"golang.org/x/sys/unix"
)

const usage = `permissions-broker - Grant a sandbox outside access while it runs

Usage:
  permissions-broker serve <config>
  permissions-broker cleanup <config>
  permissions-broker mcp [<socket>]
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
window (the command opening the Permissions window), plugins (each a
manifest path and a ceiling) and grants (the standing grants, each a
capability and its parameters, granted at start without asking). Environment variables in the paths and the window
command are expanded.

cleanup ends the grants of a daemon that stopped, as its unit's ExecStopPost:
service units stopped, folder grants detached. A daemon that starts does it too.

mcp is the MCP server inside the sandbox, a client of <socket>
(/run/permissions/request.sock by default).

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
		err = runMCP(socketArg(opts))
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
	_, err := callBroker(socket, request{Op: "share"})
	return err
}

type config struct {
	AppID         string `json:"appId"`
	Launcher      string `json:"launcher"`
	GrantDir      string `json:"grantDir"`
	ControlSocket string `json:"controlSocket"`
	// The daemon's systemd unit, which service units are bound to
	Unit            string   `json:"unit"`
	SandboxGrantDir string   `json:"sandboxGrantDir"`
	Window          []string `json:"window"`
	// Never granted as an attach source, whatever a ceiling says: every launcher's state directory and runtime
	// directory
	Denied  []string `json:"denied"`
	Plugins []struct {
		Manifest string          `json:"manifest"`
		Ceiling  json.RawMessage `json:"ceiling"`
	} `json:"plugins"`
	Grants []standingConfig `json:"grants"`
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
	caps, err := loadPlugins(cfg)
	if err != nil {
		return err
	}
	unix.Umask(0o077)
	sb, err := findSandbox(cfg.AppID)
	if err != nil {
		return err
	}
	b, err := newBroker(cfg, caps, sb, notifyAsk)
	if err != nil {
		return err
	}
	go watchLogind(b)
	return b.run()
}
