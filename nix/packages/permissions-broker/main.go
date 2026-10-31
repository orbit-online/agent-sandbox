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
  permissions-broker mcp [<socket>]
  permissions-broker share [<socket>]
  permissions-broker make-shared <path>

serve runs the daemon for one launcher, as described in docs/permissions.md:
it finds the launcher's running sandbox by app ID, listens on request.sock in
the grant directory for the sandbox and on control.sock for the Permissions
window, asks the user about each request with a notification, and ends grants
on their lease. Exits when the sandbox does. <config> is the JSON the module
writes: appId, launcher, grantDir, controlSocket, store, sandboxGrantDir,
window (the command opening the Permissions window) and plugins (each a
manifest path and a ceiling). Environment variables in the paths are expanded.

mcp is the MCP server inside the sandbox, a client of <socket>
(/run/permissions/request.sock by default).

share asks the daemon to make the grant directory a shared mount, from the
sandbox's outer mount namespace before the FHS env's bwrap copies it. Waits up
to 10 s for <socket> (/run/permissions/request.sock by default) to appear.

make-shared is the daemon's helper, run through nsenter in the sandbox's mount
namespace: it makes <path> a shared mount.
`

// Set to store paths at build time
var (
	nsenter    = "nsenter"
	notifySend = "notify-send"
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
	case opts["mcp"] == true:
		err = runMCP(socketArg(opts))
	case opts["share"] == true:
		err = share(socketArg(opts))
	case opts["make-shared"] == true:
		path, _ := opts.String("<path>")
		if err = unix.Mount("", path, "", unix.MS_SHARED, ""); err != nil {
			err = fmt.Errorf("Make %s shared: %w", path, err)
		}
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
	AppID           string   `json:"appId"`
	Launcher        string   `json:"launcher"`
	GrantDir        string   `json:"grantDir"`
	ControlSocket   string   `json:"controlSocket"`
	Store           string   `json:"store"`
	SandboxGrantDir string   `json:"sandboxGrantDir"`
	Window          []string `json:"window"`
	Plugins         []struct {
		Manifest string          `json:"manifest"`
		Ceiling  json.RawMessage `json:"ceiling"`
	} `json:"plugins"`
}

func serve(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Read config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("Parse config %s: %w", path, err)
	}
	for _, p := range []*string{&cfg.GrantDir, &cfg.ControlSocket, &cfg.Store} {
		*p = os.ExpandEnv(*p)
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
