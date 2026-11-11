package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A launch while the app's unit runs without a sandbox leaves its activation token for supervise and signals it,
// starting nothing
func TestStartActivates(t *testing.T) {
	w := newWorld(t)
	w.cfg.Tools.Systemctl = w.script("systemctl", `case "$*" in *ActiveState*) echo activating;; esac`)
	t.Setenv("XDG_ACTIVATION_TOKEN", "token-1")
	if err := startUnit(w.cfg, "config.json", nil, nil); err != nil {
		t.Fatal(err)
	}
	if token, _ := os.ReadFile(activationFile(w.cfg)); string(token) != "token-1" {
		t.Errorf("Token %q", token)
	}
	c := w.calls()
	if !strings.Contains(c, "systemctl --user kill --kill-whom=main --signal=SIGUSR1 "+w.cfg.Unit) ||
		strings.Contains(c, "systemd-run") {
		t.Errorf("Calls:\n%s", c)
	}
}

// Without a token, as from a terminal, it says where the app is instead
func TestStartRunningWithoutToken(t *testing.T) {
	w := newWorld(t)
	w.cfg.Tools.Systemctl = w.script("systemctl", `case "$*" in *ActiveState*) echo active;; esac`)
	t.Setenv("XDG_ACTIVATION_TOKEN", "")
	err := startUnit(w.cfg, "config.json", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "switch to that window") {
		t.Errorf("Ended with %v", err)
	}
	if c := w.calls(); strings.Contains(c, "kill") || strings.Contains(c, "systemd-run") {
		t.Errorf("Calls:\n%s", c)
	}
}

// A unit that doesn't run is started
func TestStartInactive(t *testing.T) {
	w := newWorld(t)
	w.cfg.Tools.Systemctl = w.script("systemctl", `case "$*" in *ActiveState*) echo inactive;; esac`)
	t.Setenv("XDG_ACTIVATION_TOKEN", "token-1")
	if err := startUnit(w.cfg, "config.json", nil, nil); err != nil {
		t.Fatal(err)
	}
	if c := w.calls(); !strings.Contains(c, "systemd-run") || strings.Contains(c, "kill") {
		t.Errorf("Calls:\n%s", c)
	}
}

// SIGUSR1 hands the left token to the splash showing the error: a failed start's, and the one shown once the app
// was up
func TestSuperviseActivate(t *testing.T) {
	for name, app := range map[string]string{
		"start":   "exit 3",
		"running": `echo "agent-sandbox: ready"; sleep 0.2; exit 3`,
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			notifySocket(t)
			splashIn := filepath.Join(w.dir, "splash-in")
			// Closes once activated, as the user would close it then
			w.cfg.Splash = []string{w.script("splash",
				`while read -r l; do echo "$l" >>`+splashIn+`; case $l in *'"activate"'*) exit;; esac; done`)}
			w.cfg.NixpakLauncher = w.script("nixpak", app)
			done := make(chan error, 1)
			go func() { done <- supervise(w.cfg, nil, nil) }()
			for i := 0; i < 200; i++ {
				if in, _ := os.ReadFile(splashIn); strings.Contains(string(in), `"error"`) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err := os.WriteFile(activationFile(w.cfg), []byte("token-1"), 0o600); err != nil {
				t.Fatal(err)
			}
			syscall.Kill(os.Getpid(), syscall.SIGUSR1)
			select {
			case err := <-done:
				var exit exitError
				if !errors.As(err, &exit) || exit != 3 {
					t.Errorf("Ended with %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("The splash wasn't activated")
			}
			if in, _ := os.ReadFile(splashIn); !strings.Contains(string(in), `{"activate":"token-1"}`) {
				t.Errorf("The splash got:\n%s", in)
			}
			if _, err := os.Stat(activationFile(w.cfg)); err == nil {
				t.Error("The token file stayed")
			}
		})
	}
}
