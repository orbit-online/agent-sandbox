package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
)

// What the sandbox reaches anyway is no holder of an ended grant: another live grant's mount, or a bind the sandbox
// started with, at or beneath the ended grant's folder

// grantFolder grants path of the folders capability c, read-only or not
func grantFolder(t *testing.T, b *broker, c *capability, path string, ro bool) *grant {
	t.Helper()
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), fmt.Sprintf(`{"path": %q, "ro": %v}`, path, ro), "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// P5: a folder granted twice, read-only and read-write, and a folder beneath it granted too: the end of one lists no
// process for the mounts of those still live
func TestHoldersOtherGrant(t *testing.T) {
	src := t.TempDir()
	if err := os.Mkdir(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow", "allow", "allow")
	c := folders(t, `{"path": "`+src+`", "rw": true}`)
	b.caps[c.id()] = c
	ro := grantFolder(t, b, c, src, true)
	rw := grantFolder(t, b, c, src, false)
	sub := grantFolder(t, b, c, filepath.Join(src, "sub"), true)
	holders, err := b.revoke(rw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 0 {
		t.Errorf("The read-write grant ended with the read-only one and the subfolder's live: holders %+v", holders)
	}
	if holders, err = b.revoke(ro.ID); err != nil || len(holders) != 0 {
		t.Errorf("The read-only grant ended with the subfolder's live: holders %+v, %v", holders, err)
	}
	if holders, err = b.revoke(sub.ID); err != nil || len(holders) != 0 {
		t.Errorf("The subfolder's grant ended: holders %+v, %v", holders, err)
	}
}

// P5: a read-write re-bind of a grant in a nested mount namespace is a holder though a read-only grant of the same
// folder is still live: that one gives no write access
func TestHoldersOtherGrantReadOnly(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow", "allow")
	c := folders(t, `{"path": "`+src+`", "rw": true}`)
	b.caps[c.id()] = c
	grantFolder(t, b, c, src, true)
	rw := grantFolder(t, b, c, src, false)
	pid := threadHold(t, stdin, out, rw.Path, rw.Path, "bindprivate")
	holders, err := b.revoke(rw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 1 || holders[0].Pid != pid || holders[0].Possible {
		t.Errorf("Holders %+v, want %d with its read-write re-bind alone", holders, pid)
	}
}

// P5: a bind the sandbox started with, of a folder beneath the grant's, makes nobody a holder of the grant
func TestHoldersStaticBind(t *testing.T) {
	src, at := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, stdin, out := sandboxC(t, "allow")
	fmt.Fprintf(stdin, "bind %s %s\n", filepath.Join(src, "sub"), at)
	if line, _ := out.ReadString('\n'); line != "ok\n" {
		t.Fatalf("The stand-in's bind: %q", line)
	}
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g := grantFolder(t, b, c, src, true)
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == b.sb.pid }) || len(holders) != 0 {
		t.Errorf("A bind the sandbox started with made holders: %+v", holders)
	}
}

// sharedGroup is the peer group of the mount at point in the mount namespace of pid, none when it isn't shared there
func sharedGroup(pid int, point string) string {
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[4] != point {
			continue
		}
		for _, o := range f[6:] {
			if g, ok := strings.CutPrefix(o, "shared:"); ok {
				return g
			}
		}
	}
	return ""
}

// P5: the grant's peer group is free once it's detached, and the next shared mount gets its id. One of another
// filesystem, made in the sandbox's mount namespace before the scan reads it, is no copy of the grant
func TestHoldersGroupReused(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g := grantFolder(t, b, c, src, true)
	group := sharedGroup(b.sb.pid, g.Path)
	if group == "" {
		t.Fatal("The grant's mount isn't shared in the sandbox")
	}
	reused := false
	mounts.ScanStarts = func() {
		// Shared mounts take the lowest free id: the grant's, unless another below it was free
		for range 20 {
			at := t.TempDir()
			fmt.Fprintf(stdin, "run mount -t tmpfs tmpfs %s && mount --make-shared %s\n", at, at)
			var pid int
			if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
				t.Fatal(pid, err)
			}
			var got string
			waitUntil(t, "a shared mount in the sandbox", func() bool {
				got = sharedGroup(b.sb.pid, at)
				return got != ""
			})
			if reused = got == group; reused {
				return
			}
		}
	}
	t.Cleanup(func() { mounts.ScanStarts = func() {} })
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reused {
		t.Skip("No shared mount got the grant's peer group")
	}
	if len(holders) != 0 {
		t.Errorf("A mount of another filesystem with the grant's old peer group made holders: %+v", holders)
	}
}

// P5: no folder is attached while the holders of an ended one are listed: the scan would take its mount, missing from
// the sandbox's mount table as it read it, for a copy of the ended grant's
func TestAttachWaitsForScan(t *testing.T) {
	src := t.TempDir()
	if err := os.Mkdir(filepath.Join(src, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _, _ := sandboxC(t, "allow", "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g := grantFolder(t, b, c, src, true)
	granted := make(chan *grant, 1)
	mounts.ScanStarts = func() {
		go func() { granted <- grantFolder(t, b, c, filepath.Join(src, "sub"), true) }()
		select {
		case <-granted:
			t.Error("A folder was attached while the holders of another were listed")
			granted <- nil
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Cleanup(func() { mounts.ScanStarts = func() {} })
	holders, err := b.revoke(g.ID)
	if err != nil || len(holders) != 0 {
		t.Errorf("Holders %+v, %v", holders, err)
	}
	<-granted
}
