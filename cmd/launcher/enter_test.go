package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A re-entry hands the sandbox none of the caller's descriptors past its standard streams: one left open across exec,
// as a shell's 3<file is, reaches a child before closeInherited and none after
func TestCloseInherited(t *testing.T) {
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	open := func() []string {
		out, err := exec.Command("sh", "-c", "echo /proc/self/fd/*").Output()
		if err != nil {
			t.Fatal(err)
		}
		var fds []string
		for _, f := range strings.Fields(string(out)) {
			fds = append(fds, strings.TrimPrefix(f, "/proc/self/fd/"))
		}
		return fds
	}
	has := func(fds []string) bool {
		for _, fd := range p {
			for _, f := range fds {
				if f == strconv.Itoa(fd) {
					return true
				}
			}
		}
		return false
	}
	if before := open(); !has(before) {
		t.Fatalf("The child didn't inherit the pipe %v: %v", p, before)
	}
	if err := closeInherited(); err != nil {
		t.Fatal(err)
	}
	if after := open(); has(after) {
		t.Errorf("The child still has the pipe %v: %v", p, after)
	}
}
