package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Started as nixpak and bwrap-subid.sh start it, with dbus.args' --control relative to $XDG_RUNTIME_DIR and the
// sandbox's pid: the control socket 0600 in a directory made 0700, live sets through it, and the proxy exiting
// when the pid does
func TestControlArgs(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	run := t.TempDir()
	sock := filepath.Join(t.TempDir(), "proxy")
	watched := exec.Command("sleep", "60")
	if err := watched.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { watched.Process.Kill(); watched.Wait() })
	cmd := exec.Command(os.Args[0], bus, sock, "--control=dbus-control/session.sock",
		"--pid="+strconv.Itoa(watched.Process.Pid), "--filter")
	cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1", "XDG_RUNTIME_DIR="+run)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })
	ctlPath := filepath.Join(run, "dbus-control", "session.sock")
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })
	for path, want := range map[string]os.FileMode{ctlPath: 0o600, filepath.Dir(ctlPath): 0o700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want mode %v", path, fi.Mode(), err, want)
		}
	}
	c := connect(t, "unix:path="+sock)
	wantErr(t, "before the grant", echo(c, svcName), errServiceUnknown)
	dialControl(t, ctlPath).must(t, map[string]any{"op": "add", "id": "g", "talk": []string{svcName}})
	wantErr(t, "after the grant", echo(c, svcName), "")
	watched.Process.Kill()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("The proxy runs on after its --pid ended")
	}
}

// --control must be a clean path relative to $XDG_RUNTIME_DIR
func TestControlArgsRefused(t *testing.T) {
	for _, rel := range []string{"/abs/sock", "../out.sock", "a/../../b", ""} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "unix:path=/x", filepath.Join(t.TempDir(), "p"), "--control="+rel)
		cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1", "XDG_RUNTIME_DIR="+t.TempDir())
		out, err := cmd.CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		if err == nil || timedOut || !strings.Contains(string(out), "--control") {
			t.Errorf("--control=%q accepted: %v %s", rel, err, out)
		}
	}
}
