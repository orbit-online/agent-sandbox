package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// world is a launcher's config whose tools are scripts of the test's, logging their calls to log
type world struct {
	t   *testing.T
	dir string
	cfg *config
	log string
}

// script writes an executable sh script to the world's bin/ and returns its path
func (w *world) script(name, body string) string {
	w.t.Helper()
	p := filepath.Join(w.dir, "bin", name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho \""+name+" $*\" >>"+w.log+"\n"+body+"\n"), 0o755); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) calls() string {
	data, _ := os.ReadFile(w.log)
	return string(data)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, dir: dir, log: filepath.Join(dir, "calls")}
	for _, d := range []string{"bin", "state/home", "runtime"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	// No session bus: no portal, no theme
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(dir, "no-bus"))
	w.cfg = &config{
		AppID:          "com.example.App",
		Unit:           "app-test.service",
		Slice:          "app-test.slice",
		StateDir:       filepath.Join(dir, "state"),
		Home:           filepath.Join(dir, "state/home"),
		Scratchpad:     filepath.Join(dir, "state/tmp-scratchpad"),
		HomeDirs:       []string{filepath.Join(dir, "state/home")},
		StoreRoots:     "/nix/store/roots",
		StoreRootsLink: "store-roots",
		Ready:          "agent-sandbox: ready",
	}
	// The store: current unless the test says otherwise
	w.cfg.State = w.script("state", `case "$*" in *store-missing*) cat >/dev/null; cat `+dir+`/missing 2>/dev/null || echo current;; *store-import*) cat >`+dir+`/imported;; esac`)
	w.cfg.Tools.NixStore = w.script("nix-store", `case "$1" in -qR) echo /nix/store/a; echo /nix/store/b;; -q) for p in "$@"; do echo 1000; done | tail -n +3;; --export) head -c 2000 /dev/zero;; esac`)
	w.cfg.Tools.Unshare = w.script("unshare", `shift 2; exec "$@"`)
	w.cfg.Tools.Systemctl = w.script("systemctl", "")
	w.cfg.Tools.SystemdRun = w.script("systemd-run", "")
	return w
}

// notifySocket listens where supervise sends sd_notify's messages and returns them as they come
func notifySocket(t *testing.T) <-chan string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	msgs := make(chan string, 8)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()
	return msgs
}

func expectMsg(t *testing.T, msgs <-chan string, want string) {
	t.Helper()
	select {
	case m := <-msgs:
		if !strings.Contains(m, want) {
			t.Errorf("Notified %q, want %q", m, want)
		}
	case <-time.After(10 * time.Second):
		t.Errorf("No %q", want)
	}
}
