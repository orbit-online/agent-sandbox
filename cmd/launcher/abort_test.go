package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Abort from the splash while the app starts: nixpak's launcher stopped with SIGTERM, the result left for start, systemd
// told, and the splash kept up for at least a second
func TestSuperviseAbort(t *testing.T) {
	w := newWorld(t)
	msgs := notifySocket(t)
	w.cfg.Splash = []string{w.script("splash", `while read -r l; do case $l in *'Starting the app'*) sleep 0.5; echo abort;; esac; done`)}
	w.cfg.NixpakLauncher = w.script("nixpak", `trap 'echo term >>`+w.log+`; exit 143' TERM; sleep 100 & wait`)
	start := time.Now()
	var exit exitError
	if err := supervise(w.cfg, nil, nil); !errors.As(err, &exit) || exit != 1 {
		t.Fatalf("Aborted with %v", err)
	}
	if took := time.Since(start); took < abortShown {
		t.Errorf("Ended %v after the abort, under %v", took, abortShown)
	}
	expectMsg(t, msgs, "READY=1")
	if msg, _ := os.ReadFile(resultFile(w.cfg)); strings.TrimSpace(string(msg)) != "Startup aborted" {
		t.Errorf("Result %q", msg)
	}
	if !strings.Contains(w.calls(), "term") {
		t.Error("nixpak's launcher wasn't stopped")
	}
}

// Ctrl-C while the app's unit starts stops the unit and ends the launcher with 130
func TestStartInterrupted(t *testing.T) {
	w := newWorld(t)
	w.cfg.Tools.SystemdRun = w.script("systemd-run", "sleep 100")
	path := filepath.Join(w.dir, "config.json")
	data, _ := json.Marshal(w.cfg)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), "LAUNCHER_TEST_MAIN=start --config="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 0; !strings.Contains(w.calls(), "systemd-run") && i < 100; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGINT)
	err := cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 130 {
		t.Errorf("Ended with %v", err)
	}
	if !strings.Contains(w.calls(), "systemctl --user stop "+w.cfg.Unit) {
		t.Errorf("The unit wasn't stopped:\n%s", w.calls())
	}
}
