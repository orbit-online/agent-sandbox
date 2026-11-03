package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// The world the state machine tests (machine_test.go) run the broker in: a sandbox stand-in as the attach tests have
// it, processes inside it as sessions and callers, and plugins faked as the other tests fake them

// How long an action waits for what the broker does on its own (a lease's end, a request returning)
const settle = 3 * time.Second

// The capabilities: services of the instances list prints, one that one launcher at a time may have and one any may,
// host commands whose call prints what it's given, and folders beneath a ceiling
const (
	capVM      = "vm/machine"
	capConsole = "vm/console"
	capToken   = "token"
	capFolder  = "folders/folder"
	// The host command's
	maxValidity = 30 * time.Minute
)

// The standing grants: a service of an instance list prints, one of the exclusive service, a command
var standingGrants = []standingConfig{
	{Capability: capConsole, Params: json.RawMessage(`{"name":"a"}`)},
	{Capability: capVM, Params: json.RawMessage(`{"name":"b"}`)},
	{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`)},
}

// fixture is what a test's iterations share: copies of the test binary named as Claude Code and as something else,
// for anchors, and the fake systemd's log
type fixture struct {
	dir, claude, node, units string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	f := &fixture{dir: t.TempDir(), units: fakeSystemd(t)}
	self, _ := os.Executable()
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*string{&f.claude, &f.node} {
		name := map[*string]string{&f.claude: "claude", &f.node: "node"}[p]
		*p = filepath.Join(f.dir, name)
		if err := os.WriteFile(*p, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// world is one iteration's: its directories, the stand-in, the plugins and the processes in the sandbox
type world struct {
	f                  *fixture
	t                  *rapid.T
	dir, root, outside string
	instances          string // what the service's list prints
	standIn            *exec.Cmd
	standInIn          io.WriteCloser
	sb                 *sandbox
	cfg                config
	host               peer
	procs              []*exec.Cmd
	pipes              []io.WriteCloser
	unitsFrom          int64 // the fake systemd's log before this iteration
	anon, forged       *caller
	sessions           map[string]*caller
	sessionsMade       int
	anchors            map[string]*exec.Cmd
}

// A process in the sandbox that sends requests: with a session (sess) or without
type caller struct {
	pid  int
	sess string
}

func newWorld(t *rapid.T, f *fixture) *world {
	dir, err := os.MkdirTemp(f.dir, "iteration-")
	if err != nil {
		t.Fatal(err)
	}
	w := &world{f: f, t: t, dir: dir, root: filepath.Join(dir, "ceiling"), outside: filepath.Join(dir, "outside"),
		instances: filepath.Join(dir, "instances"), sessions: map[string]*caller{}, anchors: map[string]*exec.Cmd{}}
	t.Cleanup(w.close)
	for _, d := range []string{w.root + "/x", w.root + "/w", w.outside, dir + "/grants", dir + "/inside"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if fi, err := os.Stat(f.units); err == nil {
		w.unitsFrom = fi.Size()
	}
	w.cfg = config{Launcher: "test", GrantDir: dir + "/grants", ControlSocket: dir + "/control.sock",
		SandboxGrantDir: dir + "/inside", Window: []string{"window"}, Grants: standingGrants}
	w.startStandIn()
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal(err)
	}
	w.host = peer{pid: os.Getpid(), pidfd: fd}
	return w
}

// startStandIn starts the sandbox: a child in a user and mount namespace of its own with the grant directory bound in,
// as standIn does
func (w *world) startStandIn() {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "BROKER_TEST=bind", "MOUNT_FROM="+w.cfg.GrantDir, "MOUNT_AT="+w.cfg.SandboxGrantDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
	}
	w.standInIn, _ = cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.standIn = cmd
	if line, _ := bufio.NewReader(out).ReadString('\n'); line != "ready\n" {
		w.t.Fatalf("Sandbox stand-in: %q", line)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	if w.sb, err = pinSandbox(cmd.Process.Pid, fd); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) close() {
	for _, c := range append(w.procs, w.standIn) {
		if c != nil && c.Process != nil {
			c.Process.Kill()
			c.Wait()
		}
	}
	if w.sb != nil {
		w.sb.close()
		unix.Close(w.sb.pidfd)
	}
	unix.Close(w.host.pidfd)
	removeLocks("test")
	removeLocks("other")
	os.RemoveAll(w.dir)
}

// inSandbox starts exe in the stand-in's user namespace, as nsenter starts a process there, without the session
// variable unless env sets it
func (w *world) inSandbox(exe string, env ...string) (*exec.Cmd, *bufio.Reader) {
	cmd := exec.Command(nsenter, fmt.Sprintf("--user=/proc/%d/ns/user", w.sb.pid), "--preserve-credentials", "--", exe)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CLAUDE_CODE_SESSION_ID=") && !strings.HasPrefix(kv, "BROKER_TEST=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	// Held open: the processes wait for its end
	in, err := cmd.StdinPipe()
	if err != nil {
		w.t.Fatal(err)
	}
	w.pipes = append(w.pipes, in)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.procs = append(w.procs, cmd)
	// Once nsenter has run exe in there
	for deadline := time.Now().Add(settle); ; time.Sleep(time.Millisecond) {
		if e, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid)); e == exe && w.sb.contains(cmd.Process.Pid) {
			break
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("%s didn't start in the sandbox", exe)
		}
	}
	return cmd, bufio.NewReader(out)
}

// session starts a Claude Code session in the sandbox: an anchor named claude and a child carrying its id
func (w *world) session() *caller {
	w.sessionsMade++
	id := "s" + strconv.Itoa(w.sessionsMade)
	anchor, pid := w.anchored(w.f.claude, id)
	c := &caller{pid: pid, sess: id}
	w.sessions[id], w.anchors[id] = c, anchor
	return c
}

// anchored starts exe as an anchor in the sandbox, with a child carrying the session id. Returns the anchor and the
// child's pid, once the child's environment is there: its exec is done when the anchor learns its pid
func (w *world) anchored(exe, id string) (*exec.Cmd, int) {
	anchor, out := w.inSandbox(exe, "BROKER_TEST=anchor", "SESSION_ID="+id)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil {
		w.t.Fatalf("Anchor of %s: %v", id, err)
	}
	for deadline := time.Now().Add(settle); ; time.Sleep(time.Millisecond) {
		if env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); strings.Contains(string(env), "CLAUDE_CODE_SESSION_ID="+id) {
			return anchor, pid
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("The session %s didn't start", id)
		}
	}
}

// endSession kills a session's anchor; its child goes with it
func (w *world) endSession(id string) {
	a := w.anchors[id]
	a.Process.Kill()
	a.Wait()
	delete(w.sessions, id)
	delete(w.anchors, id)
}

// anonymous is a process in the sandbox without a session
func (w *world) anonymous() *caller {
	if w.anon == nil {
		self, _ := os.Executable()
		cmd, _ := w.inSandbox(self, "BROKER_TEST=wait")
		w.anon = &caller{pid: cmd.Process.Pid}
	}
	return w.anon
}

// forgedSession is a process in the sandbox carrying the id of the first session, below a parent that isn't Claude
// Code: no session (P8)
func (w *world) forgedSession() *caller {
	if w.forged == nil {
		_, pid := w.anchored(w.f.node, "s1")
		w.forged = &caller{pid: pid}
	}
	return w.forged
}

// peerOfPid is the peer serveOn would find at pid, closed by the returned function
func (w *world) peerOfPid(pid int) (peer, func()) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		w.t.Fatalf("Peer %d: %v", pid, err)
	}
	return peer{pid: pid, pidfd: fd}, func() { unix.Close(fd) }
}

func (w *world) script(name, body string) []string {
	path := filepath.Join(w.dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		w.t.Fatal(err)
	}
	return []string{path}
}

// capabilities makes the plugins' capabilities
func (w *world) capabilities() map[string]*capability {
	str, boolean := json.RawMessage(`{"type": "string"}`), json.RawMessage(`{"type": "boolean"}`)
	vm := &capability{Plugin: "vm", Name: "machine", Type: "service", Description: "a VM", Exclusive: true,
		Params: map[string]json.RawMessage{"name": str, "ro": boolean}, Serve: []string{"serve"},
		List: w.script("list", "cat "+w.instances)}
	console := &capability{Plugin: "vm", Name: "console", Type: "service", Description: "a VM's console",
		Params: map[string]json.RawMessage{"name": str}, Serve: []string{"serve"}, List: vm.List}
	token := &capability{Name: "token", Type: "command", Description: "a token",
		Params: map[string]json.RawMessage{"scope": json.RawMessage(`{"type": "string", "description": "its scope"}`),
			"csr": json.RawMessage(`{"type": "string", "opaque": true, "description": "a CSR"}`)},
		Commands: map[string]*hostCommand{"issue": {Description: "issue one", Run: w.script("run", "cat"),
			MaxValidity: "PT30M"}}}
	// resolve: the path, read-only unless ro is false
	folder := &capability{Plugin: "folders", Name: "folder", Type: "attach", Description: "a folder",
		Params: map[string]json.RawMessage{"path": str, "ro": boolean}, Resolve: w.script("resolve", `in=$(cat)
path=$(printf %s "$in" | sed -n 's/.*"params":{"path":"\([^"]*\)".*/\1/p')
ro=true
case "$in" in *'"ro":false'*) ro=false ;; esac
printf '{"source":"%s","ro":%s}\n' "$path" "$ro"`),
		Ceiling: ceiling{Raw: json.RawMessage(`{"sources":[{"path":"` + w.root + `"},{"path":"` + w.root + `/w","rw":true}]}`)}}
	caps := map[string]*capability{}
	for _, c := range []*capability{vm, console, token, folder} {
		if err := c.check(); err != nil {
			w.t.Fatal(err)
		}
		caps[c.id()] = c
	}
	return caps
}

// setInstances writes what the services' list prints, and drops what list printed before
func (w *world) setInstances(cs []*capability, names []string) {
	var inst []map[string]string
	for _, n := range names {
		inst = append(inst, map[string]string{"name": n})
	}
	data, _ := json.Marshal(inst)
	if inst == nil {
		data = []byte("[]")
	}
	if err := os.WriteFile(w.instances, data, 0o600); err != nil {
		w.t.Fatal(err)
	}
	for _, c := range cs {
		c.listMu.Lock()
		c.listedAt = time.Time{}
		c.listMu.Unlock()
	}
}

// A service grant's unit; a call's is perm-test_call-<id>
var unitRe = regexp.MustCompile(`perm-test_([0-9a-f]{16})\b`)

// unitsUp reads the fake systemd's log of this iteration: the grants whose units were started and not stopped
func (w *world) unitsUp() map[string]bool {
	data, _ := os.ReadFile(w.f.units)
	up := map[string]bool{}
	for _, line := range strings.Split(string(data[w.unitsFrom:]), "\n") {
		switch {
		case strings.HasPrefix(line, "systemd-run "):
			if m := unitRe.FindStringSubmatch(line); m != nil {
				up[m[1]] = true
			}
		case strings.HasPrefix(line, "systemctl --user stop perm-test_*"):
			clear(up)
		case strings.HasPrefix(line, "systemctl --user stop "):
			for _, m := range unitRe.FindAllStringSubmatch(line, -1) {
				delete(up, m[1])
			}
		}
	}
	return up
}

// mounted lists the grants mounted in the stand-in's mount namespace, by their names in the grant directory
func (w *world) mounted() map[string]bool {
	lines, err := w.sb.mountinfo()
	if err != nil {
		w.t.Fatal(err)
	}
	names := map[string]bool{}
	for _, l := range lines {
		if name, ok := strings.CutPrefix(l.point, w.cfg.SandboxGrantDir+"/"); ok {
			names[strings.SplitN(name, "/", 2)[0]] = true
		}
	}
	return names
}

// lockHolders reads the exclusive locks: the launcher holding each of the service's instances
func lockHolders() map[string]string {
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions")
	held := map[string]string{}
	for _, n := range []string{"a", "b", "c"} {
		key, _ := json.Marshal(map[string]string{"name": n})
		if data, err := os.ReadFile(filepath.Join(dir, "vm_machine-"+hashOf(key))); err == nil {
			held[n] = strings.TrimSpace(string(data))
		}
	}
	return held
}
