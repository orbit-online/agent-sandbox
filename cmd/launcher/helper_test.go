package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// openNs refuses a pid whose process isn't the one of the pidfd any more, as after a reuse of the pid
func TestOpenNsGone(t *testing.T) {
	self, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(self)
	ns, err := openNs(os.Getpid(), self)
	if err != nil {
		t.Fatal(err)
	}
	closeNs(ns)
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	gone, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(gone)
	cmd.Wait()
	if ns, err := openNs(os.Getpid(), gone); err == nil {
		closeNs(ns)
		t.Error("Opened the namespaces of another process than the one of the pidfd")
	}
}

// What the helper runs in the netns with capabilities, ip and the launcher's network hooks, gets nothing of the
// helper's environment, which is the sandbox's: no PATH with a directory the sandbox writes ahead of the host's
func TestNetnsEnvironment(t *testing.T) {
	w := newWorld(t)
	seen := filepath.Join(w.dir, "env")
	nsenter := w.script("nsenter", "export -p >>"+seen)
	t.Setenv("PATH", "/sandbox/writes/bin:"+os.Getenv("PATH"))
	t.Setenv("OF_THE_SANDBOX", "1")
	if err := runIn(nsenter, "/hook", nil); err != nil {
		t.Fatal(err)
	}
	if err := ipIn(nsenter, "/ip", nil).Run(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/hook\n", "/ip -batch -\n"} {
		if !strings.Contains(w.calls(), want) {
			t.Errorf("calls %q lack %q", w.calls(), want)
		}
	}
	env, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"/sandbox/writes/bin", "OF_THE_SANDBOX"} {
		if strings.Contains(string(env), leaked) {
			t.Errorf("%s reached what runs in the netns: %s", leaked, env)
		}
	}
}
