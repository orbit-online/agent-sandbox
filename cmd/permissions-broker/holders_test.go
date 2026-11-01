package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// threadHoldMain holds $HOLD on one thread only, as $HOLD_MODE says: cwd (its working directory, in a filesystem
// context of its own), fd (an open file, in a file table of its own), root (chroot) or bind (a bind of it in a mount
// namespace of its own, at $HOLD_AT). The process's main thread holds nothing. Writes "ready" or the error to $READY
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

// P5: a process holding a grant on one thread alone is a holder: by that thread's working directory, open file,
// root, or a re-bind in that thread's mount namespace
func TestHoldersThreads(t *testing.T) {
	self, _ := os.Executable()
	for _, mode := range []string{"cwd", "fd", "root", "bind"} {
		t.Run(mode, func(t *testing.T) {
			src := t.TempDir()
			b, stdin, out := sandboxC(t, "allow")
			c := folders(t, `{"path": "`+src+`"}`)
			b.caps[c.id()] = c
			g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "`+src+`"}`, "PT1H"))
			if err != nil {
				t.Fatal(err)
			}
			ready := filepath.Join(t.TempDir(), "ready")
			fmt.Fprintf(stdin, "run cd / && exec env BROKER_TEST=threadhold HOLD=%s HOLD_MODE=%s HOLD_AT=%s READY=%s %s\n",
				g.Path, mode, t.TempDir(), ready, self)
			var pid int
			if _, err := fmt.Fscan(out, &pid); err != nil || pid <= 0 {
				t.Fatal(pid, err)
			}
			for range 100 {
				if data, _ := os.ReadFile(ready); len(data) > 0 {
					if string(data) != "ready" {
						t.Fatalf("The holder: %s", data)
					}
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			holders, err := b.revoke(g.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(holders, func(h holder) bool { return h.Pid == pid }) {
				t.Errorf("%d, holding the grant on a thread, isn't among the holders %+v", pid, holders)
			}
		})
	}
}
