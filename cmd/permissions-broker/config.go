package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
)

// The config the module writes, which serve and cleanup read
type config struct {
	AppID         string `json:"appId"`
	Launcher      string `json:"launcher"`
	GrantDir      string `json:"grantDir"`
	ControlSocket string `json:"controlSocket"`
	// The daemon's systemd unit, which call units are bound to
	Unit string `json:"unit"`
	// The launcher's slice, which call units join
	Slice           string   `json:"slice"`
	SandboxGrantDir string   `json:"sandboxGrantDir"`
	Window          []string `json:"window"`
	// Never granted as an attach source, whatever a ceiling says: every launcher's state directory and runtime
	// directory
	Denied []string `json:"denied"`
	// What the folders capability may grant
	Folders []mounts.Source `json:"folders"`
	// Host command and host socket capabilities
	Commands []commandConfig  `json:"commands"`
	Sockets  []socketConfig   `json:"sockets"`
	Grants   []standingConfig `json:"grants"`
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
	for i := range cfg.Window {
		cfg.Window[i] = os.ExpandEnv(cfg.Window[i])
	}
	for i := range cfg.Denied {
		cfg.Denied[i] = os.ExpandEnv(cfg.Denied[i])
	}
	if cfg.Denied, err = mounts.CheckDenied(cfg.Denied); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// loadCapabilities makes the config's capabilities: folders, host commands and host sockets
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
	return caps, nil
}
