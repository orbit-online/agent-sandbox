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
	cmd := exec.Command(os.Args[0], bus, sock, "--control=dbus-control/session.sock", "--bus=session",
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

// --control must be a clean path relative to $XDG_RUNTIME_DIR, with --bus naming a bus
func TestControlArgsRefused(t *testing.T) {
	for _, args := range [][]string{{"--control=/abs/sock", "--bus=session"}, {"--control=../out.sock", "--bus=session"},
		{"--control=a/../../b", "--bus=session"}, {"--control=", "--bus=session"}, {"--control=ok.sock", "--bus=other"},
		{"--control=ok.sock"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"unix:path=/x", filepath.Join(t.TempDir(), "p")}, args...)...)
		cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1", "XDG_RUNTIME_DIR="+t.TempDir())
		out, err := cmd.CombinedOutput()
		timedOut := ctx.Err() != nil
		cancel()
		if err == nil || timedOut || !strings.Contains(string(out), "--") {
			t.Errorf("%q accepted: %v %s", args, err, out)
		}
	}
}
