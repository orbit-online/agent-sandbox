package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// swapMain is the sandbox's swap of a mountpoint in M1, run in a user and mount namespace of its own below it (unshare
// -Urm): with an fd on the directory holding it, it pivots to a tmpfs and detaches the old root, so the mountpoint is
// no mount in its own namespace any more, and the kernel lets it rename that directory. In its place it puts
// $SWAP_FILE with $SWAP_PAYLOAD's content in a new directory, or a link to $SWAP_LINK. Writes "ok" or the error to
// $SWAP_DONE
func swapMain() {
	done, err := os.OpenFile(os.Getenv("SWAP_DONE"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		os.Exit(1)
	}
	if err := swap(); err != nil {
		fmt.Fprintln(done, err)
		os.Exit(1)
	}
	fmt.Fprintln(done, "ok")
	os.Exit(0)
}

func swap() error {
	name, link, file := os.Getenv("SWAP_NAME"), os.Getenv("SWAP_LINK"), os.Getenv("SWAP_FILE")
	payload, _ := os.ReadFile(os.Getenv("SWAP_PAYLOAD"))
	dir, err := unix.Open(os.Getenv("SWAP_DIR"), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	root := os.Getenv("SWAP_TMP")
	if err := unix.Mount("tmpfs", root, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("tmpfs: %w", err)
	}
	if err := os.Mkdir(root+"/old", 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, root+"/old"); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("Detach the old root: %w", err)
	}
	if err := unix.Renameat(dir, name, dir, name+".orig"); err != nil {
		return fmt.Errorf("Rename %s: %w", name, err)
	}
	if link != "" {
		return unix.Symlinkat(link, dir, name)
	}
	if err := unix.Mkdirat(dir, name, 0o755); err != nil {
		return err
	}
	fd, err := unix.Openat(dir, name+"/"+file, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.Write(fd, payload)
	return err
}

// attackSwap runs swapMain in the stand-in, below it, and waits for it. env: its SWAP_ variables
func attackSwap(t *testing.T, stdin io.Writer, out interface{ ReadString(byte) (string, error) }, env ...string) {
	t.Helper()
	self, _ := os.Executable()
	scratch := t.TempDir()
	done := filepath.Join(scratch, "done")
	if err := os.Mkdir(filepath.Join(scratch, "root"), 0o700); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdin, "run exec unshare -Urm env BROKER_TEST=swap SWAP_TMP=%s SWAP_DONE=%s %s %s\n",
		filepath.Join(scratch, "root"), done, strings.Join(env, " "), self)
	if line, _ := out.ReadString('\n'); strings.HasPrefix(line, "-") {
		t.Fatalf("Start the swap: %q", line)
	}
	for range 100 {
		if data, _ := os.ReadFile(done); len(data) > 0 {
			if string(data) != "ok\n" {
				t.Fatalf("The swap failed: %s", data)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("The swap didn't finish")
}

func standInCmd(t *testing.T, stdin io.Writer, out interface{ ReadString(byte) (string, error) }, cmd string) {
	t.Helper()
	fmt.Fprintln(stdin, cmd)
	if line, _ := out.ReadString('\n'); line != "ok\n" {
		t.Fatalf("%s: %q", cmd, line)
	}
}

// S12: the sandbox swaps the store directory holding the daemon's binary in M1 for its own. The helpers that act in
// M1 (make-shared, move-tree, detach) still run the daemon's binary: a grant mounts and ends, and the sandbox's never
// runs
func TestAttackStoreSwap(t *testing.T) {
	// x/store stands in for /nix/store, holding the daemon's binary on the host. In M1, x is w (the sandbox's rw /nix)
	// and x/store a bind of the host's on w/store, as nixpak binds them
	x, w := t.TempDir(), t.TempDir()
	for _, d := range []string{x + "/store", w + "/store"} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	self, _ := os.Executable()
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(x+"/store/broker", data, 0o755); err != nil {
		t.Fatal(err)
	}
	executable = func() (string, error) { return x + "/store/broker", nil }
	t.Cleanup(func() { executable = os.Executable })

	b, _ := testBroker(t, "allow")
	stdin, out := standIn(t, b)
	standInCmd(t, stdin, out, "bind "+x+"/store "+w+"/store")
	standInCmd(t, stdin, out, "bind "+w+" "+x)
	if err := b.shareFrom(peerAt(t, b.sb.pid)); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(t.TempDir(), "hijacked")
	payload := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(payload, []byte("#!/bin/sh\necho \"$@\" >>"+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	attackSwap(t, stdin, out, "SWAP_DIR="+x, "SWAP_NAME=store", "SWAP_FILE=broker", "SWAP_PAYLOAD="+payload)
	inM1 := fmt.Sprintf("/proc/%d/root%s/store/broker", b.sb.pid, x)
	if got, _ := os.ReadFile(inM1); !strings.Contains(string(got), marker) {
		t.Fatal("The swap didn't take in M1")
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	inside := fmt.Sprintf("/proc/%d/root%s/file", b.sb.pid, g.Path)
	if _, err := os.Stat(inside); err != nil {
		t.Errorf("Not mounted: %v", err)
	}
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if hijacked, err := os.ReadFile(marker); err == nil {
		t.Errorf("A helper ran the sandbox's binary: %s", hijacked)
	}
}

// The sandbox swaps the grant directory in M1 for a link to a directory where another mount of M1 sits under a grant's
// name. A revoke doesn't unmount that one
func TestAttackGrantDirSwap(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	decoys := t.TempDir()
	decoy := filepath.Join(decoys, g.ID)
	if err := os.Mkdir(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	standInCmd(t, stdin, out, "bind "+t.TempDir()+" "+decoy)
	attackSwap(t, stdin, out, "SWAP_DIR="+filepath.Dir(b.cfg.SandboxGrantDir),
		"SWAP_NAME="+filepath.Base(b.cfg.SandboxGrantDir), "SWAP_LINK="+decoys)

	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	lines, err := b.sb.mountinfo()
	if err != nil {
		t.Fatal(err)
	}
	if dev, _ := mountOf(lines, decoy); dev == "" {
		t.Error("The revoke unmounted another mount of the sandbox's, through a link in the grant directory's place")
	}
	if dev, _ := mountOf(lines, b.cfg.SandboxGrantDir+".orig/"+g.ID); dev != "" {
		t.Error("The grant is still mounted")
	}
}

// mountOf finds the device and root of the mount at mountpoint, the last one there
func mountOf(lines []mountLine, mountpoint string) (dev, root string) {
	for _, l := range lines {
		if l.point == mountpoint {
			dev, root = l.dev, l.root
		}
	}
	return dev, root
}

// P5: the sandbox renames the grant directory in M1 while a process of its has its working directory on a grant. The
// grant's mounts are known by id, not by path: the revoke still lists it
func TestAttackGrantDirRenameHolders(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(stdin, "hold %s\n", g.Path)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatalf("Holder: %d, %v", pid, err)
	}
	out.ReadString('\n')
	attackSwap(t, stdin, out, "SWAP_DIR="+filepath.Dir(b.cfg.SandboxGrantDir),
		"SWAP_NAME="+filepath.Base(b.cfg.SandboxGrantDir), "SWAP_LINK="+t.TempDir())
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h holder) bool { return h.Pid == pid }) {
		t.Errorf("%d, its working directory on the grant, isn't among the holders %+v", pid, holders)
	}
}
