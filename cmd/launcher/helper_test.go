package main

import (
	"os"
	"os/exec"
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
