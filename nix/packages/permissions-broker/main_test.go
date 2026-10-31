package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestParseDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{"PT1H": time.Hour, "PT30M": 30 * time.Minute, "PT1H30M": 90 * time.Minute,
		"PT2S": 2 * time.Second} {
		if got, err := parseDuration(s); err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "PT", "1H", "PT0H", "P1D", "PT1h", "session"} {
		if _, err := parseDuration(s); err == nil {
			t.Errorf("parseDuration(%q) accepted", s)
		}
	}
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

func TestValidate(t *testing.T) {
	c := testCap(t, "B")
	got, err := c.validate(json.RawMessage(`{"ro": true, "path": "/a"}`))
	if err != nil || string(got) != `{"path":"/a","ro":true}` {
		t.Errorf("validate = %s, %v; want sorted keys", got, err)
	}
	for _, bad := range []string{`{"other": 1}`, `{"ro": "yes"}`, `{"path": 1}`, `[1]`} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate(%s) accepted", bad)
		}
	}
	if d := c.describe(got); d != `the test thing (path="/a", ro=true)` {
		t.Errorf("describe = %q", d)
	}
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

func TestConsent(t *testing.T) {
	b, f := testBroker(t, "deny", "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c

	if _, _, err := b.request(os.Getpid(), request{Op: "request", Capability: c.id(), Lease: "PT1H"}); err == nil {
		t.Error("Granted without a reason")
	}
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Error("Granted when the user denied")
	}
	g, cred, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatalf("Not granted when the user allowed: %v", err)
	}
	if f.asked[1].Summary != `the test thing (path="/a")` || f.asked[1].Reason != "testing" {
		t.Errorf("Asked %+v", f.asked[1])
	}
	// The credential's validity is the shorter of the lease's remainder and maxValidity
	var in pluginInput
	if err := json.Unmarshal([]byte(cred), &in); err != nil || in.Validity != "PT3600S" {
		t.Errorf("Issued with %q (%v), want the lease's hour", in.Validity, err)
	}
	// A live grant covers the same request without asking; other parameters ask again
	if again, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "PT1H")); err != nil || again.ID != g.ID {
		t.Errorf("Same request got %v, %v", again, err)
	}
	if f.count() != 2 {
		t.Errorf("Asked %d times, want 2", f.count())
	}
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a", "ro": true}`, "PT1H")); err == nil {
		t.Error("Other parameters granted without asking")
	}
}

func TestRefusalLimit(t *testing.T) {
	b, f := testBroker(t)
	c := testCap(t, "B")
	b.caps[c.id()] = c
	for i := range maxRefusals {
		if _, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H")); err == nil {
			t.Fatalf("Request %d granted", i)
		}
	}
	_, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H"))
	if err == nil || !strings.Contains(err.Error(), "in a row") || f.count() != maxRefusals {
		t.Errorf("After %d refusals: %v, asked %d times", maxRefusals, err, f.count())
	}
	b.skew.Store(int64(blockFor + time.Second))
	f.answers = []string{"allow"}
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Errorf("Not asked again after the block: %v", err)
	}
}

func TestAlwaysOnlyFromWindow(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "always"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Lease != "PT1H" || len(b.store.Always) != 0 {
		t.Errorf("A notification's Allow on always gave lease %q, stored %v", g.Lease, b.store.Always)
	}
}

func TestWindowAnswer(t *testing.T) {
	b, _ := testBroker(t, "options")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	go func() {
		for {
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				if p.Options {
					id = p.ID
				}
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(request{Pending: id, Allow: true, Lease: "always", Params: json.RawMessage(`{"path": "/a", "ro": true}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Lease != "always" || string(g.Params) != `{"path":"/a","ro":true}` {
		t.Errorf("Window's answer gave %+v", g)
	}
	// Stored with exact parameters: read-only doesn't cover read-write
	if !b.isAlways(c, json.RawMessage(`{"path":"/a","ro":true}`)) || b.isAlways(c, json.RawMessage(`{"path":"/a"}`)) {
		t.Errorf("Always grants: %v", b.store.Always)
	}
	b2, err := newBroker(b.cfg, b.caps, b.sb, nil)
	if err != nil || len(b2.store.Always) != 1 {
		t.Errorf("Store not saved: %v, %v", b2.store.Always, err)
	}
}

func TestDurationLease(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1S"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.ended:
	case <-time.After(3 * time.Second):
		t.Error("A one-second lease didn't end")
	}
}

func TestLockLease(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "lock")); err == nil {
		t.Error("Lock lease granted without the screen lock watched")
	}
	b.lockOK = true
	g, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	b.lockEvent("test lock")
	select {
	case <-g.ended:
	case <-time.After(time.Second):
		t.Error("The lock didn't end the lease")
	}
}

func TestTypeA(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	b.cfg.Unit = "daemon.service"
	c := testCap(t, "A")
	b.caps[c.id()] = c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != "/run/permissions/"+g.ID+".sock" {
		t.Errorf("Socket %q", g.Socket)
	}
	if err := b.release(g.ID, "test"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	unit := unitName("test", g.ID)
	for _, bound := range []string{"--property=BindsTo=daemon.service", "--socket-property=BindsTo=daemon.service"} {
		if !strings.Contains(string(data), bound) {
			t.Errorf("Not bound to the daemon (%s):\n%s", bound, data)
		}
	}
	if !strings.Contains(string(data), "--unit="+unit+" --socket-property=ListenStream="+filepath.Join(b.cfg.GrantDir, g.ID+".sock")) ||
		!strings.Contains(string(data), "systemctl --user stop "+unit+".socket "+unit+".service") {
		t.Errorf("systemd calls:\n%s", data)
	}
}

func TestExclusive(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	other, _ := testBroker(t, "allow", "allow") // both now see its XDG_RUNTIME_DIR, the host-wide lock directory
	other.cfg.Launcher = "other"
	c := testCap(t, "A")
	c.Exclusive = true
	b.caps[c.id()], other.caps[c.id()] = c, c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/vm"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.request(os.Getpid(), req(c.id(), `{"path": "/vm"}`, "PT1H")); err == nil ||
		!strings.Contains(err.Error(), "launcher test") {
		t.Errorf("Another launcher got an exclusive instance: %v", err)
	}
	_ = b.release(g.ID, "test")
	if _, _, err := other.request(os.Getpid(), req(c.id(), `{"path": "/vm"}`, "PT1H")); err != nil {
		t.Errorf("Not granted once released: %v", err)
	}
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

func TestSession(t *testing.T) {
	anchor, child := startAnchor(t, "claude")
	s, err := sessionOf(child, os.Getpid())
	if err != nil || s == nil {
		t.Fatalf("sessionOf = %v, %v", s, err)
	}
	if s.id != "session-1" || s.anchor != anchor.Process.Pid {
		t.Errorf("Session %q anchored at %d, want session-1 at %d", s.id, s.anchor, anchor.Process.Pid)
	}
	unix.Close(s.pidfd)

	// The session lease ends with the anchor
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	g, _, err := b.request(child, req(c.id(), `{}`, "session"))
	if err != nil {
		t.Fatal(err)
	}
	if sessions := b.view(g).Sessions; !slices.Equal(sessions, []string{"session-1"}) {
		t.Errorf("Grant tied to %q", sessions)
	}
	anchor.Process.Kill()
	select {
	case <-g.ended:
	case <-time.After(10 * time.Second):
		t.Error("The session lease outlived its anchor")
	}
}

func TestSessionNeedsClaude(t *testing.T) {
	_, child := startAnchor(t, "not-claude")
	if s, err := sessionOf(child, os.Getpid()); err != nil || s != nil {
		t.Errorf("Anchored at a process that isn't Claude Code: %v, %v", s, err)
	}
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if _, _, err := b.request(child, req(c.id(), `{}`, "session")); err == nil {
		t.Error("Session lease granted without a session")
	}
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

func TestShare(t *testing.T) {
	dir := t.TempDir()
	cmd := ownNs(t, dir)
	pid := cmd.Process.Pid
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := testBroker(t)
	b.sb = &sandbox{pid: pid, pidfd: fd}
	b.cfg.SandboxGrantDir = dir

	if err := b.shareFrom(os.Getpid()); err == nil {
		t.Error("Shared for a client outside the sandbox's mount namespace")
	}
	if err := b.shareFrom(pid); err != nil {
		t.Fatal(err)
	}
	info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	for _, line := range strings.Split(string(info), "\n") {
		f := strings.Fields(line)
		if len(f) > 6 && f[4] == dir {
			if !strings.Contains(line, " shared:") {
				t.Errorf("Not shared: %s", line)
			}
			return
		}
	}
	t.Errorf("No mount at %s:\n%s", dir, info)
}

func TestControlFromHostOnly(t *testing.T) {
	b, _ := testBroker(t)
	cmd := ownNs(t, t.TempDir())
	if res := b.handleControl(nil, cmd.Process.Pid, request{Op: "state"}); res.Error == "" {
		t.Error("control.sock answered a peer in another user namespace")
	}
	if res := b.handleControl(nil, os.Getpid(), request{Op: "state"}); res.Error != "" {
		t.Errorf("control.sock refused the host: %s", res.Error)
	}
}

// Through the sockets, as the MCP server and the window talk to the broker
func TestSockets(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)

	watch, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer watch.Close()
	_ = json.NewEncoder(watch).Encode(request{Op: "watch"})
	time.Sleep(50 * time.Millisecond)

	res, err := callBroker(sock, req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil || res.Grant == nil || res.Credential == "" {
		t.Fatalf("request: %+v, %v", res, err)
	}
	list, err := callBroker(sock, request{Op: "list"})
	if err != nil || len(list.Capabilities) != 1 || len(list.Grants) != 1 {
		t.Errorf("list: %+v, %v", list, err)
	}
	if _, err := callBroker(sock, request{Op: "release", Grant: res.Grant.ID}); err != nil {
		t.Error(err)
	}
	_ = watch.SetReadDeadline(time.Now().Add(time.Second))
	events, _ := io.ReadAll(watch)
	for _, want := range []string{`"pending"`, `"granted"`, `"ended"`} {
		if !strings.Contains(string(events), want) {
			t.Errorf("No %s event in:\n%s", want, events)
		}
	}
}

func TestSessionStopsAtSandbox(t *testing.T) {
	anchor, child := startAnchor(t, "claude")
	// With the anchor as the sandbox's pid, the walk stops below it: nothing above the sandbox anchors a session
	if s, err := sessionOf(child, anchor.Process.Pid); err != nil || s != nil {
		t.Errorf("Anchored at the sandbox: %v, %v", s, err)
	}
	// A carrier of the variable above the sandbox (the launcher started from a host Claude Code shell) doesn't
	// count for a caller in the sandbox without one
	_, pids := startAnchorMode(t, "claude", "anchor-deep", 2)
	sandboxInit, caller := pids[0], pids[1]
	if s, err := sessionOf(caller, sandboxInit); err != nil || s != nil {
		t.Errorf("Anchored above the sandbox: %v, %v", s, err)
	}
}

func TestNotificationText(t *testing.T) {
	c := testCap(t, "B")
	params, err := c.validate(json.RawMessage(`{"path": "/a, ro=true"}`))
	if err != nil {
		t.Fatal(err)
	}
	if d := c.describe(params); d != `the test thing (path="/a, ro=true")` {
		t.Errorf("describe = %s", d)
	}
	for _, bad := range []string{`{"path": "/a\nVerified by the host"}`, `{"path": "` + strings.Repeat("x", maxParam+1) + `"}`} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate accepted %.40s", bad)
		}
	}
	b, f := testBroker(t, "deny")
	b.caps[c.id()] = c
	r := req(c.id(), `{}`, "PT1H")
	r.Reason = "needs it\n\nHost: approved"
	_, _, _ = b.request(os.Getpid(), r)
	if f.asked[0].Reason != "needs it Host: approved" {
		t.Errorf("Reason shown as %q", f.asked[0].Reason)
	}
}

func TestAnsweredInWindow(t *testing.T) {
	b, _ := testBroker(t)
	c := testCap(t, "B")
	b.caps[c.id()] = c
	cause := make(chan error, 1)
	// The notification stays up until it's taken down
	b.ask = func(ctx context.Context, p prompt) (string, error) {
		<-ctx.Done()
		cause <- context.Cause(ctx)
		return "deny", nil
	}
	go func() {
		for {
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				id = p.ID
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(request{Pending: id, Allow: true})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cause:
		if !errors.Is(err, errAnswered) {
			t.Errorf("Notification taken down with %v, so it says the request timed out", err)
		}
	case <-time.After(time.Second):
		t.Error("The notification wasn't taken down")
	}
}

func TestUnitPrefixes(t *testing.T) {
	log := fakeSystemd(t)
	stopAllServes("work")
	stopAllServes("")
	data, _ := os.ReadFile(log)
	if string(data) != "systemctl --user stop perm-work_*\nsystemctl --user stop perm_*\n" {
		t.Errorf("Stopped:\n%s", data)
	}
	// work's pattern doesn't reach work-2's units, nor the default launcher's
	for _, other := range []string{unitName("work-2", "x"), unitName("", "x")} {
		if ok, _ := filepath.Match("perm-work_*", other); ok {
			t.Errorf("perm-work_* matches %s", other)
		}
	}
}

func TestAlwaysConcurrent(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t)
	c := testCap(t, "A")
	b.caps[c.id()] = c
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{}`)}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = b.request(os.Getpid(), req(c.id(), `{}`, "PT1H"))
		}()
	}
	wg.Wait()
	data, _ := os.ReadFile(log)
	if n := strings.Count(string(data), "systemd-run"); n != 1 {
		t.Errorf("%d units started for one always grant", n)
	}
	if len(b.store.Log) != 0 {
		t.Errorf("Always hits logged: %d", len(b.store.Log))
	}
}

func TestRanOut(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	// The lease is over, its timer not yet fired: no credential without a validity
	b.skew.Store(int64(2 * time.Hour))
	if _, cred, err := b.request(os.Getpid(), req(c.id(), `{}`, "PT1H")); err == nil {
		t.Errorf("Issued %q after the lease ran out", cred)
	}
}

func TestBrokenStore(t *testing.T) {
	b, _ := testBroker(t)
	if err := os.WriteFile(b.cfg.Store, []byte(`{"always": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBroker(b.cfg, b.caps, b.sb, nil); err != nil {
		t.Errorf("A broken store keeps the daemon from starting: %v", err)
	}
	if _, err := os.Stat(b.cfg.Store + ".broken"); err != nil {
		t.Errorf("The broken store wasn't set aside: %v", err)
	}
}

// The sandbox holding every connection it can get leaves control.sock to the host, and request.sock frees up as idle
// clients time out
func TestServeLimits(t *testing.T) {
	old := readTimeout
	readTimeout = 500 * time.Millisecond
	t.Cleanup(func() { readTimeout = old })
	b, _ := testBroker(t)
	dir := t.TempDir()
	reqSock, ctlSock := filepath.Join(dir, "request.sock"), filepath.Join(dir, "control.sock")
	reqLn, err := listen(reqSock)
	if err != nil {
		t.Fatal(err)
	}
	defer reqLn.Close()
	ctlLn, err := listen(ctlSock)
	if err != nil {
		t.Fatal(err)
	}
	defer ctlLn.Close()
	go b.serveOn(reqLn, b.handleRequest)
	go b.serveOn(ctlLn, b.handleControl)

	var idle []net.Conn
	for range maxConns + 10 {
		c, err := net.Dial("unix", reqSock)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	if _, err := callBroker(ctlSock, request{Op: "state"}); err != nil {
		t.Errorf("control.sock with request.sock full: %v", err)
	}
	time.Sleep(readTimeout + 200*time.Millisecond)
	if _, err := callBroker(reqSock, request{Op: "list"}); err != nil {
		t.Errorf("request.sock after the idle clients timed out: %v", err)
	}
	// An oversized request is cut off, not read whole
	c, err := net.Dial("unix", reqSock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go func() {
		_, _ = c.Write([]byte(`{"op": "list", "reason": "` + strings.Repeat("x", 2*maxRequest) + `"}`))
	}()
	var res response
	if err := json.NewDecoder(c).Decode(&res); err != nil || res.Error == "" {
		t.Errorf("Oversized request answered %+v, %v", res, err)
	}
}

func TestCheckDenied(t *testing.T) {
	for _, bad := range []string{"", "relative", "./x"} {
		if _, err := checkDenied([]string{bad}); err == nil {
			t.Errorf("checkDenied accepted %q", bad)
		}
	}
	dir := t.TempDir()
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if got, err := checkDenied([]string{filepath.Join(dir, "link")}); err != nil || got[0] != dir {
		t.Errorf("checkDenied = %v, %v; want the link resolved", got, err)
	}
}

func TestCheckSource(t *testing.T) {
	ceil := ceilingC{Sources: []source{{Path: "/srv/notes"}, {Path: "/srv/work", RW: true}, {Path: "/srv/work/keep-ro"},
		{Path: "/dev/kvm"}}}
	denied := []string{"/srv/work/state"}
	for _, ok := range []struct {
		src       string
		ro        bool
		root, rel string
	}{
		{"/srv/notes", true, "/srv/notes", "."},
		{"/srv/notes/a/../b", true, "/srv/notes", "b"},
		{"/srv/work/x", false, "/srv/work", "x"},
		{"/srv/work/keep-ro/x", true, "/srv/work/keep-ro", "x"},
		{"/dev/kvm", true, "/dev/kvm", "."},
	} {
		root, rel, err := checkSource(ceil, denied, ok.src, ok.ro)
		if err != nil || root != ok.root || rel != ok.rel {
			t.Errorf("checkSource(%s) = %s, %s, %v", ok.src, root, rel, err)
		}
	}
	for _, bad := range []struct {
		src string
		ro  bool
	}{
		{"/srv/notes", false},       // read-only only
		{"/srv/notesx", true},       // not beneath, only a prefix of the name
		{"/srv/notes/../etc", true}, // out by ..
		{"srv/notes", true},         // relative
		{"/srv/work/state/x", true}, // denied
		{"/srv/work", true},         // holds a denied directory
		{"/srv", true},
		{"/srv/work/keep-ro/x", false}, // the longest source decides, and it's read-only
	} {
		if _, _, err := checkSource(ceil, denied, bad.src, bad.ro); err == nil {
			t.Errorf("checkSource(%s, ro=%v) accepted", bad.src, bad.ro)
		}
	}
}

// folders is a type C capability like the folders plugin: resolve takes path and ro (read-only unless false)
func folders(t *testing.T, sources string) *capability {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolve")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
exec sed -n 's/.*"params":{"path":"\([^"]*\)"\(,"ro":false\)\{0,1\}}.*/{"source":"\1","ro":RO\2}/p' |
  sed 's/RO,"ro":false/false/; s/RO/true/'
`), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &capability{Plugin: "folders", Name: "folder", Type: "C", Description: "a folder",
		Params:  map[string]json.RawMessage{"path": json.RawMessage(`{"type": "string"}`), "ro": json.RawMessage(`{"type": "boolean"}`)},
		Resolve: []string{path}, Ceiling: ceiling{Raw: json.RawMessage(`{"sources": [` + sources + `]}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	return c
}

// sandboxC is a broker on a sandbox stand-in: a child in a user and mount namespace of its own, with the grant
// directory bound in from outside and shared, as the launcher has it. Returns the child's stdin and stdout for hold
func sandboxC(t *testing.T, answers ...string) (*broker, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	b, _ := testBroker(t, answers...)
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := t.TempDir() // stands in for /run/permissions
	b.cfg.SandboxGrantDir = inside
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "BROKER_TEST=bind", "MOUNT_FROM="+b.cfg.GrantDir, "MOUNT_AT="+inside)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The user's ids as themselves, as the sandbox maps them, so the helpers keep their capabilities through
		// nsenter's exec only as ambient ones (--keep-caps). A uts namespace of its own, as the sandbox has, which
		// the clone helper joins for that. The child itself keeps CAP_SYS_ADMIN for its bind mount the same way
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
	}
	stdin, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	out := bufio.NewReader(stdoutPipe)
	if line, _ := out.ReadString('\n'); line != "ready\n" {
		t.Fatalf("Sandbox stand-in: %q", line)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	b.sb = &sandbox{pid: cmd.Process.Pid, pidfd: fd}
	if err := b.shareFrom(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	return b, stdin, out
}

func TestFolder(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, hold, held := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c

	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.Summary, strconv.Quote(src)+", read-only") || g.Source != src {
		t.Errorf("Grant %+v", g)
	}
	inside := fmt.Sprintf("/proc/%d/root%s", b.sb.pid, g.Path)
	if data, err := os.ReadFile(inside + "/file"); err != nil || string(data) != "notes" {
		t.Fatalf("In the sandbox: %q, %v", data, err)
	}
	if err := os.WriteFile(inside+"/new", nil, 0o600); !errors.Is(err, unix.EROFS) {
		t.Errorf("Writing to a read-only grant: %v", err)
	}
	info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", b.sb.pid))
	for _, line := range strings.Split(string(info), "\n") {
		if f := strings.Fields(line); len(f) > 5 && f[4] == g.Path {
			for _, opt := range []string{"ro", "nodev", "nosuid"} {
				if !slices.Contains(strings.Split(f[5], ","), opt) {
					t.Errorf("Mounted without %s: %s", opt, line)
				}
			}
		}
	}
	// Not in our own mount namespace: the grant directory outside holds only the empty mountpoint
	if entries, _ := os.ReadDir(filepath.Join(b.cfg.GrantDir, g.ID)); len(entries) != 0 {
		t.Errorf("The mount reached the host: %v", entries)
	}

	fmt.Fprintf(hold, "hold %s\n", g.Path)
	var holderPid int
	if _, err := fmt.Fscan(held, &holderPid); err != nil || holderPid <= 0 {
		t.Fatalf("Holder: %d, %v", holderPid, err)
	}
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].Pid != holderPid {
		t.Errorf("Holders %+v, want %d", holders, holderPid)
	}
	if _, err := os.Stat(inside + "/file"); err == nil {
		t.Error("Still mounted after the revoke")
	}
	if _, err := os.Lstat(filepath.Join(b.cfg.GrantDir, g.ID)); err == nil {
		t.Error("The mountpoint is left")
	}
	if err := b.endHolders([]int{os.Getpid()}); err == nil {
		t.Error("Ended a process outside the sandbox")
	}
	if err := b.endHolders([]int{holderPid}); err != nil {
		t.Error(err)
	}
}

func TestFolderLinkOut(t *testing.T) {
	src, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(src, "out")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	if g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+src+`/out"}`, "PT1H")); err == nil {
		t.Errorf("Followed a link out of the ceiling: %+v", g)
	}
	if entries, _ := os.ReadDir(b.cfg.GrantDir); len(entries) != 0 {
		t.Errorf("Mountpoint left after a failed grant: %v", entries)
	}
}

func TestFolderOutsideCeiling(t *testing.T) {
	b, f := testBroker(t)
	b.shared = true
	c := folders(t, `{"path": "/srv/notes"}`)
	b.caps[c.id()] = c
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/etc"}`, "PT1H")); err == nil || f.count() != 0 {
		t.Errorf("Outside the ceiling: %v, asked %d times", err, f.count())
	}
	if _, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "/srv/notes", "ro": false}`, "PT1H")); err == nil || f.count() != 0 {
		t.Errorf("Read-write where the ceiling says read-only: %v, asked %d times", err, f.count())
	}
}

// A session lease two sessions hold lasts until both end
func TestSessionsShare(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	anchor1, child1 := startAnchor(t, "claude")
	g, _, err := b.request(child1, req(c.id(), `{}`, "session"))
	if err != nil {
		t.Fatal(err)
	}
	// The second session's id differs: its anchor sets the same variable, so give it another
	anchor2, child2 := startAnchor(t, "claude")
	s2, err := sessionOf(child2, os.Getpid())
	if err != nil || s2 == nil {
		t.Fatal(s2, err)
	}
	s2.id = "session-2"
	if !b.addSession(g, s2) {
		t.Fatal("Second session not added")
	}
	anchor1.Process.Kill()
	time.Sleep(6 * time.Second)
	select {
	case <-g.ended:
		t.Fatal("Ended with the first of two sessions")
	default:
	}
	anchor2.Process.Kill()
	select {
	case <-g.ended:
	case <-time.After(10 * time.Second):
		t.Error("Outlived both sessions")
	}
}

// A daemon started again while the sandbox runs takes over the shared grant directory and replays always grants
func TestAdoptShared(t *testing.T) {
	src := t.TempDir()
	b, _, _ := sandboxC(t)
	c := folders(t, `{"path": "`+src+`"}`)
	again, err := newBroker(b.cfg, map[string]*capability{c.id(): c}, b.sb, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.endAll("test over") })
	again.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{"path":"` + src + `"}`)}}
	again.adoptShared()
	for range 50 {
		if gs := again.liveGrants(""); len(gs) == 1 {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", b.sb.pid, gs[0].Path)); err != nil {
				t.Error(err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("The always folder wasn't replayed")
}

// The sandbox's attacks on type C, from its rw binds, which may lie under a ceiling root

// A ceiling root swapped for a link to elsewhere
func TestAttackRootSwap(t *testing.T) {
	ws, secret := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(ws, "proj")
	b, _, _ := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+root+`"}`)
	b.caps[c.id()] = c
	if err := os.Symlink(secret, root); err != nil {
		t.Fatal(err)
	}
	if g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+root+`"}`, "PT1H")); err == nil {
		t.Errorf("Mounted %s through a link in place of the ceiling root", g.Source)
	}
}

// A link beneath the root to a denied directory
func TestAttackDeniedLink(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	for _, d := range []string{filepath.Join(root, "ws"), state} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../state", filepath.Join(root, "ws", "x")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow")
	b.cfg.Denied = []string{state}
	c := folders(t, `{"path": "`+root+`", "rw": true}`)
	b.caps[c.id()] = c
	if g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+root+`/ws/x", "ro": false}`, "PT1H")); err == nil {
		t.Errorf("Mounted %s, a denied directory, through a link", g.Source)
	}
}

// A denied directory under another name than the config's (a link the config's path goes through): found by
// identity, whether the source is it or holds it
func TestDeniedByIdentity(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(state, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(state, filepath.Join(elsewhere, "state")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow", "allow")
	b.cfg.Denied = []string{filepath.Join(elsewhere, "state")} // lexically unrelated to root
	c := folders(t, `{"path": "`+root+`"}`)
	b.caps[c.id()] = c
	for _, p := range []string{state + "/inner", root} {
		if g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+p+`"}`, "PT1H")); err == nil {
			t.Errorf("Mounted %s, which is or holds a denied directory", g.Source)
		}
	}
}

// A re-bind of a grant in a nested mount namespace outlives the revoke: reported as a holder
func TestAttackKeepBind(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := t.TempDir()
	b, run, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(run, "run exec unshare -Urm sh -c 'mount --rbind %s %s && exec sleep 60'\n", g.Path, keep)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatal(pid, err)
	}
	time.Sleep(500 * time.Millisecond)
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h holder) bool { return h.Pid == pid }) {
		t.Errorf("The re-bind's process %d isn't among the holders %+v", pid, holders)
	}
}

type echoIn struct {
	Text string `json:"text"`
}

// fakePlugin serves MCP on a unix socket, as a type A plugin with tools does on its grant socket: one tool, echo
func fakePlugin(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plugin.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	server := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Echoes."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Text}}}, nil, nil
		})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ss, err := server.Connect(context.Background(), &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
				if err == nil {
					_ = ss.Wait()
				}
			}()
		}
	}()
	return path
}

// rawPlugin answers MCP by hand, as the VM test's plugin does: the bare minimum of the protocol, one tool, echo
func rawPlugin(t *testing.T) string {
	t.Helper()
	return rawPluginWith(t, false, "echo")
}

// rawPluginWith is rawPlugin with tools of the given names, all echoing, or with hang one that accepts connections
// and never answers, as a plugin socket systemd accepts on while the plugin is stuck
func rawPluginWith(t *testing.T, hang bool, names ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if hang {
					io.Copy(io.Discard, conn)
					return
				}
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					var msg struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
						Params struct {
							ProtocolVersion string         `json:"protocolVersion"`
							Name            string         `json:"name"`
							Arguments       map[string]any `json:"arguments"`
						} `json:"params"`
					}
					if json.Unmarshal(sc.Bytes(), &msg) != nil || msg.ID == nil {
						continue
					}
					var result any
					switch msg.Method {
					case "initialize":
						result = map[string]any{"protocolVersion": msg.Params.ProtocolVersion,
							"capabilities": map[string]any{"tools": map[string]any{}},
							"serverInfo":   map[string]any{"name": "raw", "version": "0"}}
					case "tools/list":
						var tools []any
						for _, name := range names {
							tools = append(tools, map[string]any{"name": name, "description": "Echoes " + name + ".",
								"inputSchema": map[string]any{"type": "object",
									"properties": map[string]any{"text": map[string]any{"type": "string"}}}})
						}
						result = map[string]any{"tools": tools}
					case "tools/call":
						result = map[string]any{"content": []any{map[string]any{"type": "text",
							"text": fmt.Sprint(msg.Params.Name, ": ", msg.Params.Arguments["text"])}}}
					default:
						out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID,
							"error": map[string]any{"code": -32601, "message": msg.Method}})
						conn.Write(append(out, '\n'))
						continue
					}
					out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": result})
					conn.Write(append(out, '\n'))
				}
			}()
		}
	}()
	return path
}

func TestPluginToolsRaw(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	c := testCap(t, "A")
	c.Plugin, c.Tools = "vm", true
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)
	plugin := rawPlugin(t)
	server := newMCPServer(sock, nil, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tools := newPluginTools(sock, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, nil)
	tools.server = server
	go tools.follow(ctx)
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for range 50 {
		out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "vm_echo", Arguments: map[string]any{"text": "hi"}})
		if err == nil && !out.IsError && len(out.Content) > 0 && out.Content[0].(*mcp.TextContent).Text == "echo: hi" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("No echo through a plugin speaking bare MCP")
}

// A type A plugin's tools appear in the MCP server while its grant lives, calls reach the plugin, and they go with
// the grant, each change announced with list_changed
func TestPluginTools(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow", "allow")
	c := testCap(t, "A")
	c.Plugin, c.Tools = "vm", true
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)

	plugin := fakePlugin(t)
	server := newMCPServer(sock, nil, func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The grant's socket is wherever systemd would have put it; the fake plugin stands in for it
	tools := newPluginTools(sock, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, nil)
	tools.server = server
	go tools.follow(ctx)

	changed := make(chan struct{}, 8)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) { changed <- struct{}{} },
	})
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	has := func() bool {
		res, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(res.Tools, func(t *mcp.Tool) bool { return t.Name == "vm_echo" })
	}
	waitChanged := func(what string) {
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("No list_changed %s", what)
		}
	}

	if has() {
		t.Fatal("A plugin tool before its grant")
	}
	res, err := callBroker(sock, req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	waitChanged("for the grant")
	if !has() {
		t.Fatal("No plugin tool while its grant lives")
	}
	out, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "vm_echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil || len(out.Content) == 0 || out.Content[0].(*mcp.TextContent).Text != "echo: hi" {
		t.Fatalf("Forwarded call: %+v, %v", out, err)
	}
	for len(changed) > 0 {
		<-changed
	}
	// A second grant of it (another VM) offers its tools under names of their own
	res2, err := callBroker(sock, req(c.id(), `{"path": "/other"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	waitChanged("for the second grant")
	second := "vm_echo_" + res2.Grant.ID[:7]
	list, _ := cs.ListTools(ctx, nil)
	if !slices.ContainsFunc(list.Tools, func(t *mcp.Tool) bool { return t.Name == second }) || !has() {
		t.Errorf("Tools with two grants: %v", list.Tools)
	}
	for len(changed) > 0 {
		<-changed
	}
	if _, err := callBroker(sock, request{Op: "release", Grant: res.Grant.ID}); err != nil {
		t.Fatal(err)
	}
	waitChanged("for the release")
	if has() {
		t.Error("The plugin tool outlived its grant")
	}
	list, _ = cs.ListTools(ctx, nil)
	if !slices.ContainsFunc(list.Tools, func(t *mcp.Tool) bool { return t.Name == second }) {
		t.Error("Releasing one grant took the other's tools")
	}
}

func TestObjectSchema(t *testing.T) {
	if !objectSchema(map[string]any{"type": "object"}) || objectSchema(map[string]any{"type": "string"}) || objectSchema(nil) ||
		objectSchema(map[string]any{"type": []string{"object"}}) || objectSchema(map[string]any{"properties": map[string]any{}}) {
		t.Error("objectSchema")
	}
}

func TestNudge(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	n := &nudger{socket: sock, now: func() time.Time { return now }}
	if note := n.note(); note != "" {
		t.Errorf("Nudged about a fresh grant: %s", note)
	}
	now = now.Add(nudgeAfter + time.Minute)
	if note := n.note(); !strings.Contains(note, "the test thing") {
		t.Errorf("No nudge after %s: %q", nudgeAfter, note)
	}
	if note := n.note(); note != "" {
		t.Errorf("Nudged again right away: %s", note)
	}
}

// pluginHarness is a broker serving request.sock with a type A capability with tools, and the MCP server following
// it, its plugin connections dialled by dial. Returns a client session of the MCP server and the broker's socket
func pluginHarness(t *testing.T, dial func(string) (net.Conn, error), answers ...string) (*broker, string, *mcp.ClientSession) {
	t.Helper()
	fakeSystemd(t)
	b, _ := testBroker(t, answers...)
	c := testCap(t, "A")
	c.Plugin, c.Tools = "vm", true
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go b.serveOn(ln, b.handleRequest)
	server := newMCPServer(sock, nil, func() {})
	tools := newPluginTools(sock, dial, nil)
	tools.server = server
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go tools.follow(ctx)
	st, ct := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return b, sock, cs
}

// toolNames polls the MCP server's tools until want holds, for up to three seconds
func waitTools(t *testing.T, cs *mcp.ClientSession, want func([]string) bool) []string {
	t.Helper()
	var names []string
	for range 60 {
		res, err := cs.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		names = names[:0]
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		if want(names) {
			return names
		}
		time.Sleep(50 * time.Millisecond)
	}
	return names
}

// A plugin that accepts and never answers holds up only its own grant's tools, and its grant is tried again once
// the offer times out: when the plugin answers, its tools come
func TestPluginHangs(t *testing.T) {
	oldOffer, oldSync := offerTimeout, syncEvery
	offerTimeout, syncEvery = 300*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { offerTimeout, syncEvery = oldOffer, oldSync })
	hung, healthy := rawPluginWith(t, true), rawPluginWith(t, false, "echo")
	var first string
	recovered := false
	var mu sync.Mutex
	dial := func(path string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if first == "" {
			first = path
		}
		if path == first && !recovered {
			return net.Dial("unix", hung)
		}
		return net.Dial("unix", healthy)
	}
	_, sock, cs := pluginHarness(t, dial, "allow", "allow")
	if _, err := callBroker(sock, req("vm/thing", `{"path": "/hung"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := callBroker(sock, req("vm/thing", `{"path": "/healthy"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	names := waitTools(t, cs, func(n []string) bool {
		return slices.ContainsFunc(n, func(s string) bool { return strings.HasPrefix(s, "vm_echo") })
	})
	if !slices.ContainsFunc(names, func(s string) bool { return strings.HasPrefix(s, "vm_echo") }) {
		t.Errorf("A hanging plugin held up another grant's tools: %v", names)
	}
	mu.Lock()
	recovered = true
	mu.Unlock()
	echoes := func(n []string) bool {
		return len(slices.DeleteFunc(slices.Clone(n), func(s string) bool { return !strings.HasPrefix(s, "vm_echo") })) == 2
	}
	if names := waitTools(t, cs, echoes); !echoes(names) {
		t.Errorf("The plugin that hung isn't tried again: %v", names)
	}
}

// An offer that failed is tried again, without a grant event
func TestPluginRetry(t *testing.T) {
	oldSync := syncEvery
	syncEvery = 200 * time.Millisecond
	t.Cleanup(func() { syncEvery = oldSync })
	plugin := rawPlugin(t)
	var mu sync.Mutex
	failed := false
	dial := func(string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if !failed {
			failed = true
			return nil, errors.New("not up yet")
		}
		return net.Dial("unix", plugin)
	}
	_, sock, cs := pluginHarness(t, dial, "allow")
	if _, err := callBroker(sock, req("vm/thing", `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if names := waitTools(t, cs, func(n []string) bool { return slices.Contains(n, "vm_echo") }); !slices.Contains(names, "vm_echo") {
		t.Errorf("A failed offer wasn't tried again: %v", names)
	}
}

// Two of a grant's tools that come out under one name: the second gets the grant's id, and neither replaces the other
func TestPluginNameCollision(t *testing.T) {
	plugin := rawPluginWith(t, false, "a.b", "a_b")
	_, sock, cs := pluginHarness(t, func(string) (net.Conn, error) { return net.Dial("unix", plugin) }, "allow")
	res, err := callBroker(sock, req("vm/thing", `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	second := "vm_a_b_" + res.Grant.ID[:7]
	names := waitTools(t, cs, func(n []string) bool { return slices.Contains(n, second) })
	for name, want := range map[string]string{"vm_a_b": "a.b: x", second: "a_b: x"} {
		out, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: map[string]any{"text": "x"}})
		if err != nil || out.IsError || out.Content[0].(*mcp.TextContent).Text != want {
			t.Errorf("%s calls %+v, %v; want %q (tools %v)", name, out, err, want, names)
		}
	}
}

// The nudge reaches tool results
func TestNudgeAdds(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(b.cfg.GrantDir, "request.sock")
	ln, err := listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go b.serveOn(ln, b.handleRequest)
	if _, err := callBroker(sock, req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	n := &nudger{socket: sock, now: func() time.Time { return time.Now().Add(nudgeAfter + time.Minute) }}
	res, _, _ := n.add(&mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "result"}}}, nil, nil)
	if len(res.Content) != 2 || !strings.Contains(res.Content[1].(*mcp.TextContent).Text, "release") {
		t.Errorf("No nudge in the result: %+v", res.Content)
	}
	var none *nudger
	if res, _, _ := none.add(&mcp.CallToolResult{}, nil, nil); res == nil {
		t.Error("A nil nudger dropped the result")
	}
}

// What a daemon leaves when it stops, a crash included, ExecStopPost ends: its units, its locks, its folder grants
func TestCleanup(t *testing.T) {
	log := fakeSystemd(t)
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow")
	b.cfg.Launcher = "work"
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, _, err := b.request(os.Getpid(), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	inside := fmt.Sprintf("/proc/%d/root%s/file", b.sb.pid, g.Path)
	if _, err := os.Stat(inside); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions", "x")
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte("work\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The daemon is gone (its grants still in its memory): cleanup knows them only from the sandbox and the host
	cleanup(b.cfg, b.sb)
	if _, err := os.Stat(inside); err == nil {
		t.Error("The folder grant is still mounted")
	}
	if _, err := os.Lstat(filepath.Join(b.cfg.GrantDir, g.ID)); err == nil {
		t.Error("Its mountpoint is left")
	}
	if _, err := os.Stat(lock); err == nil {
		t.Error("The launcher's lock is left")
	}
	if data, _ := os.ReadFile(log); !strings.Contains(string(data), "systemctl --user stop perm-work_*") {
		t.Errorf("Type A units not stopped:\n%s", data)
	}
	// Without the sandbox, what's left on the host goes all the same
	if err := os.Mkdir(filepath.Join(b.cfg.GrantDir, "stale"), 0o700); err != nil {
		t.Fatal(err)
	}
	cleanup(b.cfg, nil)
	if _, err := os.Lstat(filepath.Join(b.cfg.GrantDir, "stale")); err == nil {
		t.Error("A stale mountpoint is left")
	}
}
