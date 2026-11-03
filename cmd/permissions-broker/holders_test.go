package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mounts"
	"golang.org/x/sys/unix"
)

// threadHoldMain holds $HOLD on one thread only, as $HOLD_MODE says: cwd (its working directory, in a filesystem
// context of its own), fd (an open file, in a file table of its own), root (chroot), bind (a bind of it in a mount
// namespace of its own, at $HOLD_AT) or opentree (a clone of it by open_tree, in no mount table: in a mount namespace
// of its own, whose copy of the grant at $HOLD_GRANT it unmounts) or map (a shared mapping of it, its fd closed). The process's main thread holds nothing. Writes "ready" or the
// error to $READY
func threadHoldMain() {
	// The main thread, the thread group leader, stays this goroutine's: the holder is another thread
	runtime.LockOSThread()
	errs := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		path := os.Getenv("HOLD")
		var err error
		switch os.Getenv("HOLD_MODE") {
		case "cwd":
			if err = unix.Unshare(unix.CLONE_FS); err == nil {
				err = unix.Chdir(path)
			}
		case "fd":
			if err = unix.Unshare(unix.CLONE_FILES); err == nil {
				_, err = unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
			}
		case "root":
			if err = unix.Unshare(unix.CLONE_FS); err == nil {
				err = unix.Chroot(path)
			}
		case "bind":
			if err = unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err == nil {
				err = unix.Mount(path, os.Getenv("HOLD_AT"), "", unix.MS_BIND, "")
			}
		case "map":
			var fd int
			if fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
				_, err = unix.Mmap(fd, 0, 1, unix.PROT_READ, unix.MAP_SHARED)
				unix.Close(fd)
			}
		case "opentree":
			if err = unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err == nil {
				// Private first: an unmount of a peer of M1's would propagate there
				err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
			}
			if err == nil {
				_, err = unix.OpenTree(unix.AT_FDCWD, path, unix.OPEN_TREE_CLONE)
			}
			if err == nil {
				err = unix.Unmount(os.Getenv("HOLD_GRANT"), unix.MNT_DETACH)
			}
		}
		errs <- err
		// Blocked in the kernel for good: with a file table of its own, the thread mustn't run Go's scheduler, which
		// polls the runtime's epoll fd
		for {
			unix.Syscall(unix.SYS_PAUSE, 0, 0, 0)
		}
	}()
	msg := "ready"
	if err := <-errs; err != nil {
		msg = err.Error()
	}
	os.WriteFile(os.Getenv("READY"), []byte(msg), 0o600)
	// Not select{}: with every goroutine blocked for good, the runtime ends the process
	time.Sleep(time.Hour)
}

// threadHold starts threadHoldMain in the stand-in, holding hold as mode says, and waits until it does
func threadHold(t *testing.T, stdin io.Writer, out io.Reader, grant, hold, mode string) int {
	t.Helper()
	self, _ := os.Executable()
	ready := filepath.Join(t.TempDir(), "ready")
	fmt.Fprintf(stdin, "run cd / && exec env BROKER_TEST=threadhold HOLD=%s HOLD_GRANT=%s HOLD_MODE=%s HOLD_AT=%s READY=%s %s\n",
		hold, grant, mode, t.TempDir(), ready, self)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatal(pid, err)
	}
	for range 100 {
		if data, _ := os.ReadFile(ready); len(data) > 0 {
			if string(data) != "ready" {
				t.Fatalf("The holder: %s", data)
			}
			return pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("The holder didn't start")
	return 0
}

// P5: a process holding a grant on one thread alone is a holder: by that thread's working directory, open file,
// root, a re-bind in that thread's mount namespace, or a clone of the grant in no mount namespace
func TestHoldersThreads(t *testing.T) {
	for _, mode := range []string{"cwd", "fd", "root", "bind", "opentree"} {
		t.Run(mode, func(t *testing.T) {
			src := t.TempDir()
			b, stdin, out := sandboxC(t, "allow")
			c := folders(t, `{"path": "`+src+`"}`)
			b.caps[c.id()] = c
			g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
			if err != nil {
				t.Fatal(err)
			}
			pid := threadHold(t, stdin, out, g.Path, g.Path, mode)
			holders, err := b.revoke(g.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid && !h.Possible }) {
				t.Errorf("%d, holding the grant on a thread, isn't among the holders %+v", pid, holders)
			}
		})
	}
}

// Ending a holder works on one that ignores SIGTERM: the window's End sends SIGKILL
func TestEndIgnoresTerm(t *testing.T) {
	src := t.TempDir()
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	// exec keeps the ignored signal
	fmt.Fprintf(stdin, "run trap '' TERM && cd %s && exec sleep 600\n", g.Path)
	var pid int
	if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
		t.Fatal(pid, err)
	}
	for range 100 {
		if comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); string(comm) == "sleep\n" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid }) {
		t.Fatalf("%d isn't among the holders %+v", pid, holders)
	}
	if err := b.endHeld(g.ID); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		// A zombie until the stand-in reaps it, which startTime doesn't count
		if _, ok := mounts.StartTime(pid); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("%d, ignoring SIGTERM, still runs after End", pid)
}

// P5: a file of the grant's filesystem on a detached mount that the daemon can't tie to the grant's files, here a
// clone of a file of the grant, which /proc names "/", makes its process a possible holder
func TestHoldersPossible(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, stdin, out := sandboxC(t, "allow")
	c := folders(t, `{"path": "`+src+`"}`)
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	pid := threadHold(t, stdin, out, g.Path, g.Path+"/file", "opentree")
	holders, err := b.revoke(g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid && h.Possible }) {
		t.Errorf("%d, holding a clone of a file of the grant, isn't a possible holder in %+v", pid, holders)
	}
}

// P5: a shared mapping of a file of the grant, its fd closed, makes its process a holder; a possible one once the file
// is deleted
func TestHoldersMapping(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprint("deleted=", deleted), func(t *testing.T) {
			src := t.TempDir()
			if err := os.MkdirAll(filepath.Join(src, "dir"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "dir", "file"), []byte("notes"), 0o600); err != nil {
				t.Fatal(err)
			}
			b, stdin, out := sandboxC(t, "allow")
			c := folders(t, `{"path": "`+src+`"}`)
			b.caps[c.id()] = c
			g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
			if err != nil {
				t.Fatal(err)
			}
			pid := threadHold(t, stdin, out, g.Path, g.Path+"/dir/file", "map")
			if deleted {
				if err := os.Remove(filepath.Join(src, "dir", "file")); err != nil {
					t.Fatal(err)
				}
			}
			holders, err := b.revoke(g.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(holders, func(h mounts.Holder) bool { return h.Pid == pid && h.Possible == deleted }) {
				t.Errorf("%d, mapping a file of the grant, isn't among the holders %+v", pid, holders)
			}
		})
	}
}
