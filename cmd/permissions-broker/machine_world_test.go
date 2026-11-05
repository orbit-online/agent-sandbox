package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostsock"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"golang.org/x/sys/unix"
	"pgregory.net/rapid"
)

// The world the state machine tests (machine_test.go) run the broker in: a sandbox stand-in as the attach tests have
// it, a process inside it as the caller, and on the host the instances: a directory each, with an echo server on its
// console socket

// How long an action waits for what the broker does on its own (a lease's end, a request returning)
const settle = 3 * time.Second

// The capabilities: host commands on the instances, one launcher at a time; the instances' host sockets; host
// commands whose call prints what it's given; and folders beneath a ceiling
const (
	capVM      = "vm"
	capConsole = "console"
	capToken   = "token"
	capFolder  = foldersID
	// The host command's
	maxValidity = 30 * time.Minute
)

// The standing grants: a host socket of an instance, a grant of the exclusive host commands and a host command
var standingGrants = []standingConfig{
	{Capability: capConsole, Params: json.RawMessage(`{"name":"a"}`)},
	{Capability: capVM, Params: json.RawMessage(`{"name":"b"}`)},
	{Capability: capToken, Params: json.RawMessage(`{"scope":"read"}`)},
}

// fixture is what a test's iterations share: a directory and the fake systemd's log
type fixture struct {
	dir, units string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	return &fixture{dir: t.TempDir(), units: fakeSystemd(t)}
}

// world is one iteration's: its directories, the stand-in, the instances and the process in the sandbox
type world struct {
	f                  *fixture
	t                  *rapid.T
	dir, root, outside string
	standIn            *exec.Cmd
	standInIn          io.WriteCloser
	sb                 *sandbox
	cfg                config
	host               peer
	procs              []*exec.Cmd
	pipes              []io.WriteCloser
	anon               *caller
	// The instances' echo servers, by name
	echoes map[string]*echoServer
}

// A process in the sandbox that sends requests
type caller struct {
	pid int
}

func newWorld(t *rapid.T, f *fixture) *world {
	dir, err := os.MkdirTemp(f.dir, "iteration-")
	if err != nil {
		t.Fatal(err)
	}
	w := &world{f: f, t: t, dir: dir, root: filepath.Join(dir, "ceiling"), outside: filepath.Join(dir, "outside"),
		echoes: map[string]*echoServer{}}
	t.Cleanup(w.close)
	for _, d := range append(ceilingDirs(w.root), w.outside, dir+"/grants", dir+"/inside") {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A link the sandbox could have planted beneath the ceiling, leading out of it
	if err := os.Symlink(w.outside, w.root+"/x/link"); err != nil {
		t.Fatal(err)
	}
	w.cfg = config{Launcher: "test", GrantDir: dir + "/grants", ControlSocket: dir + "/control.sock",
		SandboxGrantDir: dir + "/inside", Window: []string{"window"}, Grants: standingGrants, Denied: []string{w.root + "/d/secret"}}
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
	for _, e := range w.echoes {
		e.stop()
	}
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

// inSandbox starts exe in the stand-in's user namespace, as nsenter starts a process there
func (w *world) inSandbox(exe string, env ...string) (*exec.Cmd, *bufio.Reader) {
	cmd := exec.Command("nsenter", fmt.Sprintf("--user=/proc/%d/ns/user", w.sb.pid), "--preserve-credentials", "--", exe)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "BROKER_TEST=") {
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

// anonymous is a process in the sandbox
func (w *world) anonymous() *caller {
	if w.anon == nil {
		self, _ := os.Executable()
		cmd, _ := w.inSandbox(self, "BROKER_TEST=wait")
		w.anon = &caller{pid: cmd.Process.Pid}
	}
	return w.anon
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

// capabilities makes the capabilities
func (w *world) capabilities() map[string]*capability {
	glob := filepath.Join(w.dir, "instances", "*", "console.sock")
	name := json.RawMessage(fmt.Sprintf(declVMName, glob))
	vm := &capability{Name: capVM, Type: "command", Description: "a VM", Title: "use a VM", Exclusive: true,
		Params:   map[string]json.RawMessage{"name": name, "ro": json.RawMessage(declRO)},
		Commands: map[string]*hostcmd.Command{"start": {Description: "start it", Consent: "Start it", Run: w.script("start", "cat")}}}
	console := &capability{Name: capConsole, Type: "socket", Description: "a VM's console",
		Params: map[string]json.RawMessage{"name": name}}
	token := &capability{Name: capToken, Type: "command", Description: "a token", Title: "get a token",
		Params: map[string]json.RawMessage{"scope": json.RawMessage(declScope), "csr": json.RawMessage(declCSR),
			"slot": json.RawMessage(declSlot)},
		Commands: map[string]*hostcmd.Command{
			"issue": {Description: "issue one", Consent: "Issue one", Run: w.script("run", "cat"), MaxValidity: "PT30M"},
			"sign": {Description: "sign something", Consent: "Sign anything", Run: w.script("sign", "cat"), MaxValidity: "PT30M",
				Arguments: rawArgs(signArgs)},
		}}
	caps := map[string]*capability{}
	for _, c := range []*capability{vm, console, token} {
		if err := c.check(); err != nil {
			w.t.Fatal(err)
		}
		caps[c.id()] = c
	}
	folder, err := foldersCap([]mounts.Source{{Path: w.root}, {Path: w.root + "/w", RW: true}})
	if err != nil {
		w.t.Fatal(err)
	}
	caps[folder.id()] = folder
	return caps
}

// setInstances makes the instances names, each a directory with an echo server on its console socket, and ends the
// others, their connections included
func (w *world) setInstances(cs []*capability, names []string) {
	for n, e := range w.echoes {
		if !slices.Contains(names, n) {
			e.stop()
			delete(w.echoes, n)
		}
	}
	for _, n := range names {
		if w.echoes[n] == nil {
			w.echoes[n] = startEcho(w.t, w.dir, filepath.Join("instances", n, "console.sock"))
		}
	}
	for _, c := range cs {
		c.listMu.Lock()
		c.listedAt = time.Time{}
		c.listMu.Unlock()
	}
}

// echoServer is a host socket that sends back what it reads
type echoServer struct {
	ln    *net.UnixListener
	path  string
	mu    sync.Mutex
	conns []net.Conn
}

func startEcho(t interface{ Fatal(...any) }, dir, rel string) *echoServer {
	ln, err := hostsock.Listen(dir, rel)
	if err != nil {
		t.Fatal(err)
	}
	e := &echoServer{ln: ln, path: filepath.Join(dir, rel)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.conns = append(e.conns, conn)
			e.mu.Unlock()
			go func() { _, _ = io.Copy(conn, conn); conn.Close() }()
		}
	}()
	return e
}

// stop ends the server and its connections, and removes its directory
func (e *echoServer) stop() {
	e.ln.Close()
	e.mu.Lock()
	for _, c := range e.conns {
		c.Close()
	}
	e.mu.Unlock()
	os.RemoveAll(filepath.Dir(e.path))
}

// mounted lists the grants mounted in the stand-in's mount namespace, by their names in the grant directory
func (w *world) mounted() map[string]bool {
	lines, err := w.sb.Mountinfo()
	if err != nil {
		w.t.Fatal(err)
	}
	names := map[string]bool{}
	for _, l := range lines {
		if name, ok := strings.CutPrefix(l.Point, w.cfg.SandboxGrantDir+"/"); ok {
			names[strings.SplitN(name, "/", 2)[0]] = true
		}
	}
	return names
}

// listening lists the console's addresses in the grant directory, by instance
func (w *world) listening() map[string]bool {
	entries, _ := os.ReadDir(filepath.Join(w.cfg.GrantDir, socketsDir, capConsole))
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	return names
}

// ceilingDirs are the folders beneath the ceiling's root: a source read-only, w beneath it read-write, d with a denied
// folder beneath it
func ceilingDirs(root string) []string {
	var dirs []string
	for _, d := range []string{"", "x", "x/sub", "w", "w/sub", "d", "d/secret"} {
		dirs = append(dirs, filepath.Join(root, d))
	}
	return dirs
}

// ceiling is the folders' ceiling as the oracle reads the config: the sources, the denied folder, and the folders
// there are beneath, x/link being a link
func (w *world) ceiling() *ceiling {
	c := &ceiling{sources: []folderSource{{path: w.root}, {path: w.root + "/w", rw: true}},
		denied: []string{w.root + "/d/secret"}, folders: map[string]bool{}}
	for _, d := range ceilingDirs(w.root) {
		c.folders[d] = true
	}
	return c
}

// lockHolders reads the exclusive locks: the launcher holding each of the VMs names
func lockHolders(names []string) map[string]string {
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions")
	held := map[string]string{}
	for _, n := range names {
		key, _ := json.Marshal(map[string]string{"name": n})
		if data, err := os.ReadFile(filepath.Join(dir, capVM+"-"+hashOf(key))); err == nil {
			held[n] = strings.TrimSpace(string(data))
		}
	}
	return held
}
