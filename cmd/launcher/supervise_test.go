package main

import (
	"bytes"
	"errors"
	"log/slog"
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
	if !strings.Contains(string(in), `"text":"Starting the D-Bus proxy"`) || strings.Contains(string(in), `"error"`) {
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

// fakeJournal is journalctl answering from the world's files: follow (the host side's entries as they come), host
// (all of them once), history (supervise's lines, newest first), warnings (the host side's) and sandbox (the sandbox's)
func fakeJournal(w *world) {
	w.cfg.Journal, w.cfg.SandboxJournal = "claude-desktop", "claude-desktop_sandbox"
	w.cfg.Tools.SystemdCat = w.script("systemd-cat", "cat >/dev/null")
	d := w.dir
	w.cfg.Tools.Journalctl = w.script("journalctl", `case "$*" in
*--follow*) sleep 0.3; cat `+d+`/follow 2>/dev/null; exec sleep 30;;
*--reverse*) cat `+d+`/history 2>/dev/null;;
*--priority=warning*) cat `+d+`/warnings 2>/dev/null;;
*_sandbox*) cat `+d+`/sandbox 2>/dev/null;;
*) cat `+d+`/host 2>/dev/null;;
esac`)
}

func (w *world) file(name, data string) {
	w.t.Helper()
	if err := os.WriteFile(filepath.Join(w.dir, name), []byte(data), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// The host side's markers move the splash's step on, the estimate from earlier launches its bar; what the sandbox
// gets quoted into a helper's line moves nothing
func TestSuperviseSteps(t *testing.T) {
	w := newWorld(t)
	msgs := notifySocket(t)
	fakeJournal(w)
	splashIn := filepath.Join(w.dir, "splash-in")
	w.cfg.Splash = []string{fakeSplash(w, splashIn)}
	w.file("history", `{"SYSLOG_IDENTIFIER":"claude-desktop","MESSAGE":"level=INFO msg=Started prepared=1s proxy=2s sandbox=3s ready=10s"}
`)
	w.file("follow", `{"SYSLOG_IDENTIFIER":"dbus-proxy","MESSAGE":"level=INFO msg=Listening path=/x"}
{"SYSLOG_IDENTIFIER":"dbus-proxy","MESSAGE":"level=WARN msg=Refused member=\"x msg=Step step=network\""}
{"SYSLOG_IDENTIFIER":"claude-desktop","MESSAGE":"level=INFO msg=Step step=sandbox"}
`)
	// A marker the follower didn't get before the ready line, which the files have
	w.file("host", `{"SYSLOG_IDENTIFIER":"claude-desktop","MESSAGE":"level=INFO msg=Step step=network"}
`)
	w.cfg.NixpakLauncher = w.script("nixpak", `sleep 1; echo "agent-sandbox: ready"`)
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	if err := supervise(w.cfg, nil, nil); err != nil {
		t.Fatal(err)
	}
	expectMsg(t, msgs, "READY=1")
	in, _ := os.ReadFile(splashIn)
	if !strings.Contains(string(in), `"text":"Connecting the sandbox to the network","progress":`) ||
		strings.Contains(string(in), "Starting Claude") || !strings.Contains(string(in), `{"progress":`) {
		t.Errorf("The splash got:\n%s", in)
	}
	if !strings.Contains(buf.String(), "msg=Started prepared=") || !strings.Contains(buf.String(), " sandbox=") ||
		!strings.Contains(buf.String(), " network=") {
		t.Errorf("Logged:\n%s", buf.String())
	}
}

// A failed start shows the host side's warnings, labelled, apart from the sandbox's entries, which are the app's
func TestSuperviseFailureLogs(t *testing.T) {
	w := newWorld(t)
	notifySocket(t)
	fakeJournal(w)
	splashIn := filepath.Join(w.dir, "splash-in")
	w.cfg.Splash = []string{fakeSplash(w, splashIn)}
	w.file("warnings", `{"SYSLOG_IDENTIFIER":"claude-desktop","MESSAGE":"level=WARN msg=\"No uplink yet\""}
`)
	w.file("sandbox", `{"SYSLOG_IDENTIFIER":"claude-desktop","MESSAGE":"app says hi"}
{"SYSLOG_IDENTIFIER":"probe","MESSAGE":"no peer"}
`)
	w.cfg.NixpakLauncher = w.script("nixpak", "exit 3")
	if err := supervise(w.cfg, nil, nil); err == nil {
		t.Fatal("Started")
	}
	in, _ := os.ReadFile(splashIn)
	if !strings.Contains(string(in), `"host":"claude-desktop: No uplink yet"`) ||
		!strings.Contains(string(in), `"log":"app says hi\nprobe: no peer"`) {
		t.Errorf("The splash got:\n%s", in)
	}
}
