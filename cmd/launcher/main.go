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
)

const usage = `launcher - Starts a launcher's sandbox, or joins the running one

Usage:
  launcher start --config=<file> [--vars-fd=<fd>] [--] [<arg>...]
  launcher supervise --config=<file> --vars-file=<file> [--] [<arg>...]
  launcher store-sync --config=<file>
  launcher theme --config=<file> [<scheme>]

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

Options:
  --config=<file>      The launcher's config, from the Home Manager module
  --vars-fd=<fd>       The sandbox's environment, NUL-separated, on this fd
  --vars-file=<file>   The same in a file, which supervise deletes once read
`

// The launcher's config, as launch.nix writes it
type config struct {
	AppID          string   `json:"appId"`
	Launcher       string   `json:"launcher"` // Its name, empty for the default launcher
	Unit           string   `json:"unit"`     // The app's unit
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
	Ready          string   `json:"ready"` // The line the app prints on stdout when its first window is ready
	Tools          struct {
		Nsenter    string `json:"nsenter"`
		NixStore   string `json:"nixStore"`
		Setpriv    string `json:"setpriv"`
		Systemctl  string `json:"systemctl"`
		SystemdRun string `json:"systemdRun"`
		Unshare    string `json:"unshare"`
		WrapperDir string `json:"wrapperDir"` // newuidmap and newgidmap, for unshare
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
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
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
