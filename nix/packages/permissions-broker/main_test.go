package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Re-executed as the processes the broker inspects. wait: blocks until stdin closes. anchor: starts a wait child with
// CLAUDE_CODE_SESSION_ID set, prints its pid and waits. mount: in a user and mount namespace of its own, mounts a
// tmpfs on $MOUNT_AT, prints "ready" and waits
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "make-shared" {
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
	if g.Session != "session-1" {
		t.Errorf("Grant tied to %q", g.Session)
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
