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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// folders is an attach capability like the folders plugin: resolve takes path and ro (read-only unless false)
func folders(t *testing.T, sources string) *capability {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolve")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
exec sed -n 's/.*"params":{"path":"\([^"]*\)"\(,"ro":false\)\{0,1\}}.*/{"source":"\1","ro":RO\2}/p' |
  sed 's/RO,"ro":false/false/; s/RO/true/'
`), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &capability{Plugin: "folders", Name: "folder", Type: "attach", Description: "a folder",
		Params:  map[string]json.RawMessage{"path": json.RawMessage(`{"type": "string"}`), "ro": json.RawMessage(`{"type": "boolean"}`)},
		Resolve: []string{path}, Ceiling: ceiling{Raw: json.RawMessage(`{"sources": [` + sources + `]}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	return c
}

// sandboxC is a broker on a sandbox stand-in, with the grant directory shared. Returns the stand-in's stdin and stdout
// for hold, run and bind
func sandboxC(t *testing.T, answers ...string) (*broker, io.WriteCloser, *bufio.Reader) {
	t.Helper()
	b, _ := testBroker(t, answers...)
	stdin, out := standIn(t, b)
	if err := b.shareFrom(peerAt(t, b.sb.pid)); err != nil {
		t.Fatal(err)
	}
	return b, stdin, out
}

// standIn puts b on a sandbox stand-in: a child in a user and mount namespace of its own, with the grant directory
// bound in from outside, as the launcher has it
func standIn(t *testing.T, b *broker) (io.WriteCloser, *bufio.Reader) {
	t.Helper()
	if err := os.MkdirAll(b.cfg.GrantDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(t.TempDir(), "permissions") // stands in for /run/permissions
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	b.cfg.SandboxGrantDir = inside
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), "BROKER_TEST=bind", "MOUNT_FROM="+b.cfg.GrantDir, "MOUNT_AT="+inside)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The user's ids as themselves, as the sandbox maps them, so the helpers keep their capabilities through
		// nsenter's exec only as ambient ones (--keep-caps). A uts namespace of its own, as the sandbox has, which
		// the helpers join for that. The child itself keeps CAP_SYS_ADMIN for its bind mount the same way, and its
		// children CAP_SYS_CHROOT too, for a holder by its root
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_SYS_CHROOT},
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
	return stdin, out
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
	c := testCap(t, "command")
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

// A daemon started again while the sandbox runs takes over the shared grant directory: folders are granted into it
func TestAdoptShared(t *testing.T) {
	src := t.TempDir()
	b, _, _ := sandboxC(t)
	c := folders(t, `{"path": "`+src+`"}`)
	f := &fakeAsker{answers: []string{"allow"}}
	again, err := newBroker(b.cfg, map[string]*capability{c.id(): c}, b.sb, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.endAll("test over") })
	again.adoptShared()
	g, _, err := again.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", b.sb.pid, g.Path)); err != nil {
		t.Error(err)
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
		t.Errorf("Service units not stopped:\n%s", data)
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

// share is served once
func TestShareOnce(t *testing.T) {
	b, _, _ := sandboxC(t)
	if err := b.shareFrom(peerAt(t, b.sb.pid)); err == nil {
		t.Error("share served twice")
	}
}

// The detach comes before the holders' scan, whose cost the sandbox chooses: when the scan starts, the grant is
// unmounted where the app sees it
func TestDetachFirst(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	inside := fmt.Sprintf("/proc/%d/root%s/file", b.sb.pid, g.Path)
	scanned := false
	scanStarts = func() {
		scanned = true
		if _, err := os.Stat(inside); err == nil {
			t.Error("Still mounted when the holders' scan started")
		}
	}
	t.Cleanup(func() { scanStarts = func() {} })
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if !scanned {
		t.Error("No holders' scan")
	}
}
