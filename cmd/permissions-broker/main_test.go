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
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/notify"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"golang.org/x/sys/unix"
)

// Re-executed as the processes the broker inspects. wait: blocks until stdin closes. mount: in a user and mount namespace of its own, mounts a
// tmpfs on $MOUNT_AT, prints "ready" and waits. swap: see swap_test.go. threadhold: see holders_test.go. live-agent and
// live-anchor (arguments, not BROKER_TEST, which the launcher's re-entry drops): see live_procs_test.go
func TestMain(m *testing.M) {
	liveHelper()
	if len(os.Args) > 2 && slices.Contains([]string{"make-shared", "clone-tree", "move-tree", "detach"}, os.Args[1]) {
		main()
		return
	}
	switch os.Getenv("BROKER_TEST") {
	case "wait":
		io.Copy(io.Discard, os.Stdin)
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
			// bind <from> <to>: a bind mount in the sandbox's outer mount namespace, as bwrap makes them
			if args, ok := strings.CutPrefix(sc.Text(), "bind "); ok {
				from, to, _ := strings.Cut(args, " ")
				if err := unix.Mount(from, to, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
					fmt.Println(err)
				} else {
					fmt.Println("ok")
				}
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
	case "swap":
		swapMain()
	case "threadhold":
		threadHoldMain()
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
	c := &capability{Name: "thing", Type: typ, Description: "the test thing",
		Params: map[string]json.RawMessage{
			"path": json.RawMessage(`{"type": "string", "description": "a path"}`),
			"ro":   json.RawMessage(`{"type": "boolean", "description": "read-only"}`),
		}}
	if typ == "command" {
		// A host command printing its input, so tests see the validity it was given
		fakeSystemd(t)
		c.Title = "use the test thing"
		c.Commands = map[string]*hostcmd.Command{"run": {Description: "print the input", Consent: "Print what it gets",
			Run: script("run", "cat"), MaxValidity: "PT8H"}}
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
	asked   []notify.Prompt
}

func (f *fakeAsker) ask(_ context.Context, p notify.Prompt) (string, error) {
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

// instancesIn gives c an instances glob on its bounding argument path, over a directory of the test's, and makes the
// instances names there: entries of the directory, the others removed
func instancesIn(t *testing.T, c *capability, names ...string) {
	t.Helper()
	if c.glob == "" {
		c.glob, c.globArg = filepath.Join(t.TempDir(), "*"), "path"
	}
	dir := filepath.Dir(c.glob)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		os.Remove(filepath.Join(dir, e.Name()))
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.listMu.Lock()
	c.listedAt = time.Time{}
	c.listMu.Unlock()
}

// fakeSystemd replaces systemd-run and systemctl with scripts that log their arguments. systemd-run --pipe, a host
// command's call, runs the command after --, as systemd would
func fakeSystemd(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	for _, name := range []string{"systemd-run", "systemctl"} {
		path := filepath.Join(dir, name)
		body := "#!/bin/sh\necho " + name + " \"$@\" >>" + log + "\n"
		if name == "systemd-run" {
			body += `case " $* " in *" --pipe "*) while [ "$1" != -- ]; do shift; done; shift; exec "$@" ;; esac` + "\n"
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
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
		SandboxGrantDir: "/run/permissions"}
	b, err := newBroker(cfg, map[string]*capability{}, ownSandbox(t, os.Getpid()), f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.endAll("test over") })
	return b, f
}

// callRun calls the test command capability's run under the bounding values params
func callRun(b *broker, p peer, params, lease string) (response, error) {
	return b.call(p, wire.Request{Op: "call", Capability: "thing", Command: "run", Params: json.RawMessage(params),
		Arguments: json.RawMessage(`{}`), Reason: "testing", Lease: lease})
}

// calledWith is what a call of the test command was given on stdin, which it prints
func calledWith(t *testing.T, res response) hostcmd.Input {
	t.Helper()
	var in hostcmd.Input
	if err := json.Unmarshal([]byte(res.Output), &in); err != nil {
		t.Fatalf("Call printed %q: %v", res.Output, err)
	}
	return in
}

func req(capID, params, lease string) wire.Request {
	return wire.Request{Op: "request", Capability: capID, Params: json.RawMessage(params), Reason: "testing", Lease: lease}
}

// ownNs starts the test binary as a mount process in a user, mount and uts namespace of its own, root there
func ownNs(t *testing.T, mountAt string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "BROKER_TEST=mount", "MOUNT_AT="+mountAt)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS,
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

// peerAt is a client at pid, as serveOn finds it: with a pidfd
func peerAt(t *testing.T, pid int) peer {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return peer{pid: pid, pidfd: fd}
}

// pinned is the sandbox at pid, its namespaces pinned as findSandbox does
func pinned(t *testing.T, pid, pidfd int) *sandbox {
	t.Helper()
	sb, err := pinSandbox(pid, pidfd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sb.close)
	return sb
}

// ownSandbox stands in for a sandbox at pid in our own user namespace: every process of the test's is in it
func ownSandbox(t *testing.T, pid int) *sandbox {
	t.Helper()
	userns, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { userns.Close() })
	return &sandbox{pid: pid, pidfd: -1, userns: userns}
}
