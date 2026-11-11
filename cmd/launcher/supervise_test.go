package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The app's ready line closes the splash and tells systemd the unit started; the app's output goes on to the journal
func TestSuperviseReady(t *testing.T) {
	w := newWorld(t)
	msgs := notifySocket(t)
	splashIn := filepath.Join(w.dir, "splash-in")
	w.cfg.Splash = []string{fakeSplash(w, splashIn)}
	w.cfg.NixpakLauncher = w.script("nixpak", `echo starting >&2; echo "agent-sandbox: ready"; sleep 1; echo bye`)
	done := make(chan error, 1)
	go func() { done <- supervise(w.cfg, []string{"A=1"}, []string{"claude://x"}) }()
	expectMsg(t, msgs, "READY=1")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if c := w.calls(); !strings.Contains(c, "nixpak --password-store=basic claude://x") ||
		!strings.Contains(c, "state "+w.cfg.Home+" -- home") || !strings.Contains(c, "nix-store --add-root") {
		t.Errorf("Calls:\n%s", c)
	}
	in, _ := os.ReadFile(splashIn)
	if !strings.Contains(string(in), `"text":"Starting the app"`) || strings.Contains(string(in), `"error"`) {
		t.Errorf("The splash got:\n%s", in)
	}
	if _, err := os.Stat(resultFile(w.cfg)); err == nil {
		t.Error("A result file after a start")
	}
}

// A refusal before nixpak's launcher runs goes to the result file, for start, before systemd hears the start ended
func TestSuperviseRefusal(t *testing.T) {
	w := newWorld(t)
	msgs := notifySocket(t)
	w.cfg.RequiredBinds = []string{filepath.Join(w.dir, "absent")}
	w.cfg.NixpakLauncher = w.script("nixpak", "")
	var exit exitError
	if err := supervise(w.cfg, nil, nil); !errors.As(err, &exit) || exit != 1 {
		t.Fatalf("Refused with %v", err)
	}
	expectMsg(t, msgs, "READY=1")
	msg, _ := os.ReadFile(resultFile(w.cfg))
	if !strings.Contains(string(msg), "Bind source "+filepath.Join(w.dir, "absent")+" is missing") {
		t.Errorf("Result %q", msg)
	}
	if strings.Contains(w.calls(), "nixpak") {
		t.Error("Ran nixpak's launcher after a refusal")
	}
}

// An app that ends with an error before its window is up: its status, and its last output in the splash's error
func TestSuperviseAppFails(t *testing.T) {
	w := newWorld(t)
	notifySocket(t)
	splashIn := filepath.Join(w.dir, "splash-in")
	w.cfg.Splash = []string{fakeSplash(w, splashIn)}
	w.cfg.NixpakLauncher = w.script("nixpak", "echo 'bwrap: no such file' >&2; exit 3")
	var exit exitError
	if err := supervise(w.cfg, nil, nil); !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("Ended with %v", err)
	}
	in, _ := os.ReadFile(splashIn)
	if !strings.Contains(string(in), `"error":"The app didn't start (exit status 3)."`) ||
		!strings.Contains(string(in), "bwrap: no such file") {
		t.Errorf("The splash got:\n%s", in)
	}
}

// The tail keeps the last lines within its size, the newest whole
func TestTail(t *testing.T) {
	tl := &tail{max: 10}
	for _, l := range []string{"one", "two", "three", "a very long line"} {
		tl.add(l)
	}
	if got := tl.String(); got != "a very long line" {
		t.Errorf("Tail %q", got)
	}
	tl = &tail{max: 10}
	tl.add("ab")
	tl.add("cd")
	if got := tl.String(); got != "ab\ncd" {
		t.Errorf("Tail %q", got)
	}
}

// The splash missing doesn't stop a start
func TestNoSplash(t *testing.T) {
	w := newWorld(t)
	msgs := notifySocket(t)
	w.cfg.Splash = []string{filepath.Join(w.dir, "absent")}
	w.cfg.NixpakLauncher = w.script("nixpak", `echo "agent-sandbox: ready"`)
	done := make(chan error, 1)
	go func() { done <- supervise(w.cfg, nil, nil) }()
	expectMsg(t, msgs, "READY=1")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("supervise didn't end with the app")
	}
}

// fakeSplash records what the splash is told in path, and closes as the user would once it shows an error
func fakeSplash(w *world, path string) string {
	return w.script("splash", `while read -r l; do echo "$l" >>`+path+`; case $l in *'"error"'*) exit;; esac; done`)
}
