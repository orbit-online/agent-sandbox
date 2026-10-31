package main

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Re-executed as the processes authorize inspects. wait: blocks until stdin closes. nest: also starts a wait child
// in a user namespace of its own and prints its pid
func TestMain(m *testing.M) {
	switch os.Getenv("SUBID_BROKER_TEST") {
	case "wait":
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "nest":
		child, _, err := start()
		if err != nil {
			os.Stderr.WriteString("Start a userns in the client's: " + err.Error() + "\n")
			os.Exit(1)
		}
		os.Stdout.WriteString(strconv.Itoa(child.Process.Pid) + "\n")
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// In a user namespace of its own, the caller's uid and gid mapped to 0: a process can only create one below
// that while its gid is mapped too
func ownUserns() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
}

// Starts /proc/self/exe as a wait process in a user namespace of its own. Close the returned stdin to end it
func start() (*exec.Cmd, io.WriteCloser, error) {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "SUBID_BROKER_TEST=wait")
	cmd.SysProcAttr = ownUserns()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	return cmd, stdin, cmd.Start()
}

func pidfd(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func TestParseMap(t *testing.T) {
	pid, m, err := parseMap(strings.Fields("42 0 1000 1 1 0 1000 1001 1001 64535"))
	if err != nil || pid != 42 || m != "0 1000 1\n1 0 1000\n1001 1001 64535\n" {
		t.Errorf("parseMap = %d %q %v", pid, m, err)
	}
	for _, args := range []string{"", "42", "42 0 1000", "42 0 1000 1 1", "x 0 1000 1", "42 0 -1 1", "42 0 1000 4294967296", "42 0 1000 1\n"} {
		if _, _, err := parseMap(strings.Fields(args)); err == nil && args != "42 0 1000 1\n" {
			t.Errorf("parseMap(%q) accepted", args)
		}
	}
}

func TestAuthorize(t *testing.T) {
	uid := unix.Getuid()

	// A client in a userns of its own (as the sandbox), and the target it starts in a userns below that
	client := exec.Command("/proc/self/exe")
	client.Env = append(os.Environ(), "SUBID_BROKER_TEST=nest")
	client.SysProcAttr = ownUserns()
	client.Stderr = os.Stderr
	clientIn, err := client.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	clientOut, err := client.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("Start client in a new userns: %v", err)
	}
	defer func() { clientIn.Close(); client.Wait() }()
	line, err := bufio.NewReader(clientOut).ReadString('\n')
	if err != nil {
		t.Fatalf("Read target's pid: %v", err)
	}
	target, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	// Beside the client's userns, not below it
	sibling, siblingIn, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { siblingIn.Close(); sibling.Wait() }()

	parent, dir, pid, err := authorize(pidfd(t, client.Process.Pid), uid, pidfd(t, target))
	if err != nil {
		t.Fatalf("Target below the client: %v", err)
	}
	if pid != target {
		t.Errorf("pid = %d, want %d", pid, target)
	}
	if same, _ := sameNs(int(parent.Fd()), "/proc/"+strconv.Itoa(client.Process.Pid)+"/ns/user"); !same {
		t.Error("Parent isn't the client's userns")
	}
	parent.Close()
	dir.Close()

	for _, tc := range []struct {
		name           string
		client, target int
		uid            int
		want           string
	}{
		{"client outside a sandbox", os.Getpid(), sibling.Process.Pid, uid, "Client isn't in a sandbox"},
		{"sibling userns", client.Process.Pid, sibling.Process.Pid, uid, "isn't below the client's"},
		{"client's own userns", client.Process.Pid, client.Process.Pid, uid, "isn't below the client's"},
		{"other uid", client.Process.Pid, target, uid + 1, "belongs to uid"},
	} {
		if _, _, _, err := authorize(pidfd(t, tc.client), tc.uid, pidfd(t, tc.target)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
