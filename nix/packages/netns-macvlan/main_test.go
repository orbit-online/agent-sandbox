package main

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Re-executed as the process whose netns openNetns inspects; blocks until stdin closes
func TestMain(m *testing.M) {
	if os.Getenv("NETNS_MACVLAN_TEST_CHILD") == "1" {
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStableMAC(t *testing.T) {
	id := []byte("0123456789abcdef0123456789abcdef\n")
	mac := stableMAC(id, 1000)
	// A changed derivation hands every sandbox a new DHCP lease
	if got := mac.String(); got != "0a:47:3f:c0:f2:e7" {
		t.Errorf("stableMAC = %s, want 0a:47:3f:c0:f2:e7", got)
	}
	for uid := range 64 {
		if mac := stableMAC(id, uid); mac[0]&0x01 != 0 || mac[0]&0x02 == 0 {
			t.Errorf("%s is not a locally administered unicast MAC", mac)
		}
	}
	if stableMAC(id, 1001).String() == mac.String() {
		t.Error("Same MAC for different uids")
	}
	if stableMAC([]byte("fedcba9876543210fedcba9876543210\n"), 1000).String() == mac.String() {
		t.Error("Same MAC for different machine IDs")
	}
}

func TestLowestMetric(t *testing.T) {
	for _, tc := range []struct {
		name   string
		routes []netlink.Route
		want   int
	}{
		{"none", nil, -1},
		{"no device", []netlink.Route{{LinkIndex: 0, Priority: 0}}, -1},
		{"lowest metric", []netlink.Route{{LinkIndex: 2, Priority: 600}, {LinkIndex: 3, Priority: 100}, {LinkIndex: 4, Priority: 300}}, 3},
		{"skips deviceless", []netlink.Route{{LinkIndex: 0, Priority: 0}, {LinkIndex: 5, Priority: 50}}, 5},
	} {
		if got := lowestMetric(tc.routes); got != tc.want {
			t.Errorf("%s: lowestMetric = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestOpenNetns(t *testing.T) {
	uid := unix.Getuid()

	if _, err := openNetns(os.Getpid(), uid); err == nil || !strings.Contains(err.Error(), "shares the caller's network namespace") {
		t.Errorf("Own pid: err = %v, want a shared netns error", err)
	}

	// A child in its own userns and netns, as bwrap sets up the sandbox
	child := exec.Command("/proc/self/exe")
	child.Env = append(os.Environ(), "NETNS_MACVLAN_TEST_CHILD=1")
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}},
	}
	if err := child.Start(); err != nil {
		t.Fatalf("Start child in a new userns and netns: %v", err)
	}
	pid := child.Process.Pid
	fd, err := openNetns(pid, uid)
	if err != nil {
		t.Errorf("Child's netns: %v", err)
	} else {
		unix.Close(fd)
	}
	if _, err := openNetns(pid, uid+1); err == nil {
		t.Error("Child's netns opened for a uid that doesn't own it")
	}

	stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := openNetns(pid, uid); err == nil {
		t.Error("Exited child's netns opened")
	}
}
