package main

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// The cloned tree the clone helper sends is close-on-exec once received: a host command or helper the daemon starts
// meanwhile doesn't inherit a clone of the source
func TestTreeCloseOnExec(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := unix.Sendmsg(pair[1], []byte("/src"), unix.UnixRights(int(dir.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	tree, path, err := recvTree(pair[0])
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if flags, err := unix.FcntlInt(tree.Fd(), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 || path != "/src" {
		t.Errorf("Received %s with fd flags %d, %v", path, flags, err)
	}
}
