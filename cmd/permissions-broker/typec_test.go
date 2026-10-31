package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	"golang.org/x/sys/unix"
)

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
	b.sb = pinned(t, cmd.Process.Pid, fd)
	if err := b.shareFrom(peerAt(t, cmd.Process.Pid)); err != nil {
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

	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
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
	start, _ := startTime(os.Getpid())
	if err := b.endHolders([]holder{{Pid: os.Getpid(), Start: start}}); err == nil {
		t.Error("Ended a process outside the sandbox")
	}
	if err := b.endHeld(g.ID); err != nil {
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
	if g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`/out"}`, "PT1H")); err == nil {
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
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/etc"}`, "PT1H")); err == nil || f.count() != 0 {
		t.Errorf("Outside the ceiling: %v, asked %d times", err, f.count())
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/srv/notes", "ro": false}`, "PT1H")); err == nil || f.count() != 0 {
		t.Errorf("Read-write where the ceiling says read-only: %v, asked %d times", err, f.count())
	}
}

// A session lease two sessions hold lasts until both end
func TestSessionsShare(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	anchor1, child1 := startAnchor(t, "claude")
	g, _, err := b.request(peerAt(t, child1), req(c.id(), `{}`, "session"))
	if err != nil {
		t.Fatal(err)
	}
	// The second session's id differs: its anchor sets the same variable, so give it another
	anchor2, child2 := startAnchor(t, "claude")
	s2, err := ownSandbox(t, os.Getpid()).sessionOf(child2)
	if err != nil || s2 == nil {
		t.Fatal(s2, err)
	}
	s2.id = "session-2"
	if !b.hold(g, s2) {
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
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
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

// P12: share is served once, and replays mount an always folder once however often they run
func TestReplayOnce(t *testing.T) {
	src := t.TempDir()
	b, _, _ := sandboxC(t)
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	if err := b.shareFrom(peerAt(t, b.sb.pid)); err == nil {
		t.Error("share served twice")
	}
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{"path":"` + src + `"}`)}}
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() { b.replay("C") })
	}
	wg.Wait()
	if gs := b.liveGrants(""); len(gs) != 1 {
		t.Errorf("Replays made %d grants of one always folder", len(gs))
	}
	if err := b.forget(c.id(), json.RawMessage(`{"path":"`+src+`"}`)); err != nil {
		t.Fatal(err)
	}
	if gs := b.liveGrants(""); len(gs) != 0 {
		t.Errorf("Forget left %d grants", len(gs))
	}
}
