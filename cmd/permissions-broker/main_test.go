package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Re-executed as the processes the broker inspects. wait: blocks until stdin closes. anchor: starts a wait child with
// CLAUDE_CODE_SESSION_ID set, prints its pid and waits. mount: in a user and mount namespace of its own, mounts a
// tmpfs on $MOUNT_AT, prints "ready" and waits
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && slices.Contains([]string{"make-shared", "clone-tree", "move-tree", "detach", "detach-all"}, os.Args[1]) {
		main()
		return
	}
	switch os.Getenv("BROKER_TEST") {
	case "wait":
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "anchor", "anchor-deep":
		child := "wait"
		if os.Getenv("BROKER_TEST") == "anchor-deep" {
			child = "middle"
		}
		cmd := exec.Command("/proc/self/exe")
		cmd.Env = append(os.Environ(), "BROKER_TEST="+child, "CLAUDE_CODE_SESSION_ID=session-1")
		stdin, _ := cmd.StdinPipe()
		// middle prints the pids itself
		cmd.Stdout = os.Stdout
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		if child == "wait" {
			fmt.Println(cmd.Process.Pid)
		}
		io.Copy(io.Discard, os.Stdin)
		stdin.Close()
		cmd.Wait()
		os.Exit(0)
	case "middle":
		// Below a session's carrier, a process without the variable: the sandbox's init, started from a host
		// Claude Code shell, and something in the sandbox
		cmd := exec.Command("/proc/self/exe")
		env := []string{"BROKER_TEST=wait"}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "CLAUDE_CODE_SESSION_ID=") && !strings.HasPrefix(kv, "BROKER_TEST=") {
				env = append(env, kv)
			}
		}
		cmd.Env = env
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		fmt.Println(os.Getpid(), cmd.Process.Pid)
		io.Copy(io.Discard, os.Stdin)
		stdin.Close()
		cmd.Wait()
		os.Exit(0)
	case "bind":
		// The sandbox's outer mount namespace: the grant directory bound in from outside. Then, for each "hold
		// <path>" on stdin, a child with its working directory there, whose pid it prints
		if err := unix.Mount(os.Getenv("MOUNT_FROM"), os.Getenv("MOUNT_AT"), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("ready")
		sc := bufio.NewScanner(os.Stdin)
		var held []*exec.Cmd
		for sc.Scan() {
			// run <shell command>: something in the sandbox, as a process of its own
			if script, ok := strings.CutPrefix(sc.Text(), "run "); ok {
				cmd := exec.Command("sh", "-c", script)
				cmd.Stderr = os.Stderr
				if err := cmd.Start(); err != nil {
					fmt.Println(-1)
					continue
				}
				held = append(held, cmd)
				fmt.Println(cmd.Process.Pid)
				continue
			}
			if path, ok := strings.CutPrefix(sc.Text(), "hold "); ok {
				cmd := exec.Command("/proc/self/exe")
				cmd.Env = append(os.Environ(), "BROKER_TEST=wait")
				cmd.Dir = path
				stdin, _ := cmd.StdinPipe()
				defer stdin.Close()
				if err := cmd.Start(); err != nil {
					fmt.Println(-1)
					continue
				}
				held = append(held, cmd)
				fmt.Println(cmd.Process.Pid)
			}
		}
		for _, c := range held {
			c.Process.Kill()
			c.Wait()
		}
		os.Exit(0)
	case "mount":
		if err := unix.Mount("tmpfs", os.Getenv("MOUNT_AT"), "tmpfs", 0, ""); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("ready")
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testCap(t *testing.T, typ string) *capability {
	t.Helper()
	dir := t.TempDir()
	script := func(name, body string) []string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return []string{path}
	}
	c := &capability{Plugin: "test", Name: "thing", Type: typ, Description: "the test thing",
		Params: map[string]json.RawMessage{
			"path": json.RawMessage(`{"type": "string"}`),
			"ro":   json.RawMessage(`{"type": "boolean"}`),
		}}
	switch typ {
	case "A":
		c.Serve = []string{"/bin/true"}
	case "B":
		// Prints its input, so tests see the validity it was given
		c.Issue = script("issue", "cat")
		c.Ceiling = ceiling{MaxValidity: "PT8H", Raw: json.RawMessage(`{"maxValidity": "PT8H"}`)}
	}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	return c
}

// fakeAsker answers with the next of its answers and counts the questions
type fakeAsker struct {
	mu      sync.Mutex
	answers []string
	asked   []prompt
}

func (f *fakeAsker) ask(_ context.Context, p prompt) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, p)
	if len(f.answers) == 0 {
		return "deny", nil
	}
	a := f.answers[0]
	f.answers = f.answers[1:]
	return a, nil
}

func (f *fakeAsker) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// fakeSystemd replaces systemd-run and systemctl with scripts that log their arguments
func fakeSystemd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	for _, name := range []string{"systemd-run", "systemctl"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\necho "+name+" \"$@\" >>"+log+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldRun, oldCtl := systemdRun, systemctl
	systemdRun, systemctl = filepath.Join(dir, "systemd-run"), filepath.Join(dir, "systemctl")
	t.Cleanup(func() { systemdRun, systemctl = oldRun, oldCtl })
	return log
}

func testBroker(t *testing.T, answers ...string) (*broker, *fakeAsker) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	f := &fakeAsker{answers: answers}
	cfg := config{Launcher: "test", GrantDir: filepath.Join(dir, "grants"), ControlSocket: filepath.Join(dir, "control.sock"),
		Store: filepath.Join(dir, "permissions.json"), SandboxGrantDir: "/run/permissions"}
	b, err := newBroker(cfg, map[string]*capability{}, &sandbox{pid: os.Getpid(), pidfd: -1}, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.endAll("test over") })
	return b, f
}

func req(capID, params, lease string) request {
	return request{Op: "request", Capability: capID, Params: json.RawMessage(params), Reason: "testing", Lease: lease}
}

// startAnchor starts a copy of the test binary named claude, which starts a child carrying a session id. Returns the
// anchor and the child's pid
func startAnchor(t *testing.T, name string) (*exec.Cmd, int) {
	cmd, pids := startAnchorMode(t, name, "anchor", 1)
	return cmd, pids[0]
}

func startAnchorMode(t *testing.T, name, mode string, n int) (*exec.Cmd, []int) {
	t.Helper()
	self, _ := os.Executable()
	exe := filepath.Join(t.TempDir(), name)
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "BROKER_TEST="+mode)
	stdin, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	pids := make([]int, n)
	for i := range pids {
		if _, err := fmt.Fscan(out, &pids[i]); err != nil {
			t.Fatal(err)
		}
	}
	return cmd, pids
}

// ownNs starts the test binary as a mount process in a user and mount namespace of its own, root there
func ownNs(t *testing.T, mountAt string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "BROKER_TEST=mount", "MOUNT_AT="+mountAt)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	stdin, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	var ready string
	if _, err := fmt.Fscan(out, &ready); err != nil || ready != "ready" {
		t.Fatalf("Mount process: %q, %v", ready, err)
	}
	return cmd
}
