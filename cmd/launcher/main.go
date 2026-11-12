package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/docopt/docopt-go"
	"github.com/orbit-online/agent-sandbox/internal/journal"
)

const usage = `launcher - Starts a launcher's sandbox, or joins the running one

Usage:
  launcher start --config=<file> [--vars-fd=<fd>] [--] [<arg>...]
  launcher supervise --config=<file> --vars-file=<file> [--] [<arg>...]
  launcher store-sync --config=<file>
  launcher theme --config=<file> [<scheme>]
  launcher bwrap --mode=<mode> --bwrap=<exe> --newuidmap=<exe> --newgidmap=<exe> [--subid-broker=<exe>]
                 [--permissions-broker=<exe>] [--net=<json>] [--units=<json>] [--] [<arg>...]
  launcher bwrap-helper <spec>

start is the launcher on the host's PATH. A first argument --permissions opens
the Permissions window, --shell a login shell where the app runs. A running
sandbox gets the arguments through its app (claude:// URLs). Otherwise it starts
the app's unit, whose main process is supervise, and returns once the app is
up, saying why when it didn't start.

supervise prepares the sandbox's state and store, shows a splash with the
progress meanwhile, runs nixpak's launcher with the arguments, and keeps the
sandbox's GTK theme following the desktop's colour scheme. The app's first
window closes the splash and tells systemd the unit started. When the app
ends with an error, it shows the error with the app's last output.

store-sync copies the sandbox's closure into its store, theme sets its GTK theme
from the portal's colour scheme, or <scheme> (1 dark), once.

bwrap is bwrap for the sandbox, with a range of ids mapped into its user
namespace (bwrap.go): mode subid is nixpak's bwrap on the host, with the user's
/etc/subuid range, the sandbox's cgroups and, with --net, its network; mode
parent the FHS env's inside, mapping the parent user namespace's ids as
themselves. bwrap-helper is its helper, which it starts itself.

Options:
  --config=<file>      The launcher's config, from the Home Manager module
  --vars-fd=<fd>       The sandbox's environment, NUL-separated, on this fd
  --vars-file=<file>   The same in a file, which supervise deletes once read
  --mode=<mode>        subid or parent
  --bwrap=<exe>        bwrap itself
  --newuidmap=<exe>    newuidmap (on the host the setuid wrapper, inside the
  --newgidmap=<exe>    subid-broker's shims), newgidmap the same
  --subid-broker=<exe>        subid-broker, for mode subid
  --permissions-broker=<exe>  The permissions broker, which shares
                              /run/permissions in mode parent
  --net=<json>         The network setup, for mode subid (helper.go, netSetup)
  --units=<json>       The host unit for subid-broker, for mode subid
                       (helper.go, hostUnits)
`

// The launcher's config, as launch.nix writes it
type config struct {
	AppID          string   `json:"appId"`
	Launcher       string   `json:"launcher"`       // Its name, empty for the default launcher
	Unit           string   `json:"unit"`           // The app's unit
	Journal        string   `json:"journal"`        // The journal namespace the launcher's host side logs to
	SandboxJournal string   `json:"sandboxJournal"` // The one the sandbox and the app's output log to
	Slice          string   `json:"slice"`
	AppPid         int      `json:"appPid"`
	StateDir       string   `json:"stateDir"`
	Home           string   `json:"home"` // The sandbox's home on the host
	Scratchpad     string   `json:"scratchpad"`
	HomeDirs       []string `json:"homeDirs"`
	RequiredBinds  []string `json:"requiredBinds"`
	State          string   `json:"state"` // claude-desktop-state, see confine.sh
	StoreRoots     string   `json:"storeRoots"`
	StoreRootsLink string   `json:"storeRootsLink"`
	NixpakLauncher string   `json:"nixpakLauncher"`
	Ready          string   `json:"ready"`       // The line the app prints on stdout when its first window is ready
	Nameservers    []string `json:"nameservers"` // The sandbox's DNS servers, the host's (dns.go) when empty
	Network        bool     `json:"network"`     // Off: lo alone in the netns of the sandbox, no netkit pair and no DNS
	Tools          struct {
		Journalctl string `json:"journalctl"`
		Nsenter    string `json:"nsenter"`
		NixStore   string `json:"nixStore"`
		Setpriv    string `json:"setpriv"`
		Systemctl  string `json:"systemctl"`
		SystemdRun string `json:"systemdRun"`
		SystemdCat string `json:"systemdCat"`
		Unshare    string `json:"unshare"`
		WrapperDir string `json:"wrapperDir"` // newuidmap and newgidmap, for unshare, and netns-netkit
	} `json:"tools"`
	Permissions *struct {
		Config string   `json:"config"`
		Dir    string   `json:"dir"`
		Unit   string   `json:"unit"`
		Broker string   `json:"broker"`
		Window []string `json:"window"` // The Permissions window's command, $XDG_RUNTIME_DIR expanded
	} `json:"permissions"`
	Splash []string `json:"splash"` // The splash's command, without --app-id
}

func main() {
	opts, err := docopt.ParseArgs(usage, nil, "")
	if err != nil {
		os.Exit(2)
	}
	journal.Setup()
	if opts["bwrap"] == true || opts["bwrap-helper"] == true {
		err := runTool(opts)
		if err != nil {
			slog.Error(err.Error())
		}
		endHostLog()
		if err != nil {
			os.Exit(1)
		}
		return
	}
	path, _ := opts.String("--config")
	cfg, err := loadConfig(path)
	if err == nil {
		err = run(cfg, path, opts)
	}
	if err != nil {
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintf(os.Stderr, "%s: %v\n", progName(cfg), err)
		os.Exit(1)
	}
}

func run(cfg *config, path string, opts docopt.Opts) error {
	args, _ := opts["<arg>"].([]string)
	switch {
	case opts["start"] == true:
		vars, err := readVars(opts)
		if err != nil {
			return err
		}
		return start(cfg, path, vars, args)
	case opts["supervise"] == true:
		vars, err := readVars(opts)
		if err != nil {
			return err
		}
		return supervise(cfg, vars, args)
	case opts["store-sync"] == true:
		return syncStore(cfg, nil)
	}
	scheme, _ := opts.String("<scheme>")
	return setTheme(cfg, scheme)
}

// runTool runs the subcommands that take no launcher config: bwrap and its helper
func runTool(opts docopt.Opts) error {
	if opts["bwrap-helper"] == true {
		spec, _ := opts.String("<spec>")
		return runHelper(spec)
	}
	o := bwrapOpts{}
	o.mode, _ = opts.String("--mode")
	o.bwrap, _ = opts.String("--bwrap")
	o.newuidmap, _ = opts.String("--newuidmap")
	o.newgidmap, _ = opts.String("--newgidmap")
	o.subidBroker, _ = opts.String("--subid-broker")
	o.permissionsBroker, _ = opts.String("--permissions-broker")
	if n, _ := opts.String("--net"); n != "" {
		o.net = &netSetup{}
		if err := json.Unmarshal([]byte(n), o.net); err != nil {
			return fmt.Errorf("--net: %w", err)
		}
	}
	if u, _ := opts.String("--units"); u != "" {
		o.units = &hostUnits{}
		if err := json.Unmarshal([]byte(u), o.units); err != nil {
			return fmt.Errorf("--units: %w", err)
		}
	}
	args, _ := opts["<arg>"].([]string)
	return runBwrap(o, args)
}

// On the host, bwrap and its helper log to the host side's journal namespace once they know it (hostLog), not to the
// stderr of nixpak's launcher, which supervise pumps into the sandbox's namespace with the app's output
var (
	hostOut    io.Writer = os.Stderr // Where the commands they run print
	endHostLog           = func() {}
)

func hostLog(u *hostUnits) {
	if u.SystemdCat == "" || u.Journal == "" {
		return
	}
	w, end, err := journal.Cat(u.SystemdCat, u.Journal, u.Prefix)
	if err != nil {
		slog.Warn("Logging to stderr", "err", err)
		return
	}
	prev := slog.Default()
	slog.SetDefault(slog.New(journal.Handler(w, true)))
	hostOut = w
	endHostLog = func() {
		slog.SetDefault(prev)
		hostOut = os.Stderr
		end()
		endHostLog = func() {}
	}
}

// exitError ends the launcher with its status, having said why already
type exitError int

func (e exitError) Error() string { return "exit status " + strconv.Itoa(int(e)) }

// progName is how the launcher names itself in messages: claude-desktop, as the bash launcher did
func progName(cfg *config) string {
	if cfg != nil && cfg.Launcher != "" {
		return "claude-desktop-" + cfg.Launcher
	}
	return "claude-desktop"
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Read the config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("Parse the config: %w", err)
	}
	return &cfg, nil
}

// readVars reads the sandbox's environment the wrapper expanded in bash, NUL-separated, from --vars-fd or --vars-file
func readVars(opts docopt.Opts) ([]string, error) {
	var data []byte
	if path, _ := opts.String("--vars-file"); path != "" {
		var err error
		if data, err = os.ReadFile(path); err != nil {
			return nil, fmt.Errorf("Read the sandbox's environment: %w", err)
		}
		os.Remove(path)
	} else if s, _ := opts.String("--vars-fd"); s != "" {
		fd, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("--vars-fd: %w", err)
		}
		f := os.NewFile(uintptr(fd), "vars")
		defer f.Close()
		if data, err = io.ReadAll(f); err != nil {
			return nil, fmt.Errorf("Read the sandbox's environment: %w", err)
		}
	}
	var vars []string
	for v := range strings.SplitSeq(string(data), "\x00") {
		if v != "" {
			vars = append(vars, v)
		}
	}
	return vars, nil
}
