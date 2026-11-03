package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"golang.org/x/sys/unix"
)

// movingSandbox stands in for a sandbox whose init runs the attacker's code: a process in a user and mount namespace
// of its own that, on a line on stdin, moves to new ones as the same pid (exec unshare -Um). Returns it, its stdin and
// its stdout
func movingSandbox(t *testing.T) (*exec.Cmd, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	cmd := exec.Command("unshare", "--user", "--mount", "--uts", "--map-current-user", "sh", "-c",
		`echo ready; read x; exec unshare --user --mount --map-current-user sh -c 'echo moved; read y'`)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	out := bufio.NewReader(stdout)
	if line, _ := out.ReadString('\n'); line != "ready\n" {
		t.Fatalf("Sandbox stand-in: %q", line)
	}
	return cmd, stdin, out
}

func move(t *testing.T, stdin io.Writer, out *bufio.Reader) {
	t.Helper()
	fmt.Fprintln(stdin)
	if line, _ := out.ReadString('\n'); line != "moved\n" {
		t.Fatalf("Moving: %q", line)
	}
}

// The helpers act on the namespaces the sandbox had when the daemon found it, and refuse once its pid is elsewhere
func TestPinned(t *testing.T) {
	cmd, stdin, out := movingSandbox(t)
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	sb := pinned(t, cmd.Process.Pid, fd)
	root, err := grantDirOf(config{GrantDir: "/", SandboxGrantDir: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mounts.Share(sb, root); err != nil {
		t.Fatal(err)
	}
	move(t, stdin, out)
	if err := sb.Check(); err == nil {
		t.Error("The sandbox's pid moved to other namespaces unnoticed")
	}
	if err := mounts.Share(sb, root); err == nil {
		t.Error("share went on after the sandbox's pid moved")
	}
	if _, err := sb.Mountinfo(); err == nil {
		t.Error("Read the mount table of where the sandbox's pid moved")
	}
	// Found again now, it isn't the sandbox: its user namespace isn't a child of ours
	if again, err := pinSandbox(cmd.Process.Pid, fd); err == nil {
		again.close()
		t.Error("Pinned a sandbox in a user namespace of its own making")
	}
}

// findSandbox takes the pid nixpak's instance directory names only while it is in the namespaces bwrap reported,
// below a process of ours, in a user namespace that is a child of ours
func TestLookupSandbox(t *testing.T) {
	cmd, stdin, out := movingSandbox(t)
	pid := cmd.Process.Pid
	runtime := t.TempDir()
	dir := filepath.Join(runtime, ".flatpak", "nixpak-app-1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "info"), []byte("[Application]\nname=app\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	instance := func(mnt uint64) {
		info := fmt.Sprintf(`{"child-pid": %d, "mnt-namespace": %d, "pid-namespace": %d}`, pid, mnt, nsIno(pid, "pid"))
		if err := os.WriteFile(filepath.Join(dir, "bwrapinfo.json"), []byte(info), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	instance(nsIno(pid, "mnt"))
	sb, err := lookupSandbox(runtime, "app")
	if err != nil {
		t.Fatal(err)
	}
	sb.close()
	unix.Close(sb.pidfd)
	if sb, err := lookupSandbox(runtime, "other"); err == nil {
		t.Errorf("Found another app's sandbox: %d", sb.pid)
	}
	// A stale instance: its pid is in other namespaces than bwrap made
	instance(nsIno(pid, "mnt") + 1)
	if sb, err := lookupSandbox(runtime, "app"); err == nil {
		t.Errorf("Took a stale instance's pid %d", sb.pid)
	}
	// The pid in the namespaces named, but not below ours: a nested sandbox's
	move(t, stdin, out)
	instance(nsIno(pid, "mnt"))
	if sb, err := lookupSandbox(runtime, "app"); err == nil {
		t.Errorf("Took pid %d in a user namespace that isn't a child of ours", sb.pid)
	}
}
