package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Re-executed as the process whose netns openNetns inspects; blocks until stdin closes. With "nest", it runs in a user
// namespace of its own and starts another such process below it, in a network namespace and, with
// NETNS_MACVLAN_TEST_USERNS=true, a user namespace of its own, and prints that one's pid
func TestMain(m *testing.M) {
	switch os.Getenv("NETNS_MACVLAN_TEST_CHILD") {
	case "1":
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "nest":
		flags := uintptr(syscall.CLONE_NEWNET)
		var maps []syscall.SysProcIDMap
		if os.Getenv("NETNS_MACVLAN_TEST_USERNS") == "true" {
			flags |= syscall.CLONE_NEWUSER
			maps = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}
		}
		inner, stdin, err := start(flags, maps, "1")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(inner.Process.Pid)
		io.Copy(io.Discard, os.Stdin)
		stdin.Close()
		inner.Wait()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Starts this test binary as a child in mode with clone flags, its uid map maps
func start(flags uintptr, maps []syscall.SysProcIDMap, mode string) (*exec.Cmd, io.WriteCloser, error) {
	child := exec.Command("/proc/self/exe")
	child.Env = append(os.Environ(), "NETNS_MACVLAN_TEST_CHILD="+mode)
	child.Stderr = os.Stderr
	stdin, err := child.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags, UidMappings: maps}
	if err := child.Start(); err != nil {
		return nil, nil, fmt.Errorf("Start child: %w", err)
	}
	return child, stdin, nil
}

// A child in a user namespace of its own (as root there) with a process below it, see TestMain. Returns the child,
// the pid below it and a func that ends both
func nest(t *testing.T, userns bool) (*exec.Cmd, int, func()) {
	t.Helper()
	uid := unix.Getuid()
	child := exec.Command("/proc/self/exe")
	child.Env = append(os.Environ(), "NETNS_MACVLAN_TEST_CHILD=nest", fmt.Sprintf("NETNS_MACVLAN_TEST_USERNS=%t", userns))
	child.Stderr = os.Stderr
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	// Its gid mapped too: a user namespace below it needs both
	child.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: unix.Getgid(), Size: 1}},
	}
	if err := child.Start(); err != nil {
		t.Fatalf("Start child in a new userns: %v", err)
	}
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil {
		t.Fatalf("Read the inner pid: %v", err)
	}
	return child, pid, func() {
		stdin.Close()
		child.Wait()
	}
}

func TestStableMAC(t *testing.T) {
	id := []byte("0123456789abcdef0123456789abcdef\n")
	mac := stableMAC(id, 1000, "")
	// A changed derivation hands every sandbox a new DHCP lease
	if got := mac.String(); got != "0a:47:3f:c0:f2:e7" {
		t.Errorf("stableMAC = %s, want 0a:47:3f:c0:f2:e7", got)
	}
	for uid := range 64 {
		if mac := stableMAC(id, uid, ""); mac[0]&0x01 != 0 || mac[0]&0x02 == 0 {
			t.Errorf("%s is not a locally administered unicast MAC", mac)
		}
	}
	if stableMAC(id, 1001, "").String() == mac.String() {
		t.Error("Same MAC for different uids")
	}
	if stableMAC([]byte("fedcba9876543210fedcba9876543210\n"), 1000, "").String() == mac.String() {
		t.Error("Same MAC for different machine IDs")
	}
	if stableMAC(id, 1000, "work").String() == mac.String() {
		t.Error("Same MAC for different names")
	}
	if mac := stableMAC(id, 1000, "work"); mac[0]&0x01 != 0 || mac[0]&0x02 == 0 {
		t.Errorf("%s is not a locally administered unicast MAC", mac)
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
	self := "/proc/self/ns/user"

	if _, err := openNetns(os.Getpid(), uid, self); err == nil || !strings.Contains(err.Error(), "shares the caller's network namespace") {
		t.Errorf("Own pid: err = %v, want a shared netns error", err)
	}

	// A child in its own userns and netns, as bwrap sets up the sandbox
	child, stdin, err := start(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNET, []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}, "1")
	if err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	fd, err := openNetns(pid, uid, self)
	if err != nil {
		t.Errorf("Child's netns: %v", err)
	} else {
		unix.Close(fd)
	}
	if _, err := openNetns(pid, uid+1, self); err == nil {
		t.Error("Child's netns opened for a uid that doesn't own it")
	}

	stdin.Close()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := openNetns(pid, uid, self); err == nil {
		t.Error("Exited child's netns opened")
	}
}

// The user namespace chain from the netns up to the caller's
func TestOpenNetnsChain(t *testing.T) {
	uid := unix.Getuid()
	self := "/proc/self/ns/user"

	// Two user namespaces down, as a container in the sandbox: the topmost one is the caller's
	outer, pid, end := nest(t, true)
	defer end()
	fd, err := openNetns(pid, uid, self)
	if err != nil {
		t.Errorf("Netns two user namespaces down: %v", err)
	} else {
		unix.Close(fd)
	}
	// As seen from a caller in a sibling user namespace, which the chain never meets
	sibling, siblingStdin, err := start(syscall.CLONE_NEWUSER, []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}}, "1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		siblingStdin.Close()
		sibling.Wait()
	}()
	siblingUserns := fmt.Sprintf("/proc/%d/ns/user", sibling.Process.Pid)
	if _, err := openNetns(pid, uid, siblingUserns); err == nil || !strings.Contains(err.Error(), "isn't below the caller's user namespace") {
		t.Errorf("From a sibling user namespace: err = %v, want not below", err)
	}
	// From the middle one, owned by the caller's uid there too
	if fd, err := openNetns(pid, uid, fmt.Sprintf("/proc/%d/ns/user", outer.Process.Pid)); err != nil {
		t.Errorf("From the middle user namespace: %v", err)
	} else {
		unix.Close(fd)
	}

	// A netns owned by the caller's own user namespace, as a system one is for a host caller: the owner rule gives it
	// no capability there
	outer, pid, end2 := nest(t, false)
	defer end2()
	outerUserns := fmt.Sprintf("/proc/%d/ns/user", outer.Process.Pid)
	if _, err := openNetns(pid, uid, outerUserns); err == nil || !strings.Contains(err.Error(), "caller's own user namespace") {
		t.Errorf("Netns of the caller's own user namespace: err = %v, want refused", err)
	}
}
