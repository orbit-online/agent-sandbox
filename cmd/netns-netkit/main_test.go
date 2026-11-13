package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docopt/docopt-go"
	"golang.org/x/sys/unix"
)

// What run refuses before it touches anything
func TestRunRefuses(t *testing.T) {
	long := strings.Repeat("a", 47)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"up", "--name=Work", "1"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=1x"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=" + long}, "is not [a-z][a-z0-9-]*"},
		{[]string{"down", "--name=a/../b"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"grant", "tcp", "0"}, "is not 1 to 65535"},
		{[]string{"grant", "udp", "65536"}, "is not 1 to 65535"},
		{[]string{"revoke", "tcp", "http"}, "is not 1 to 65535"},
		{[]string{"revoke", "--all", "--name=Work"}, "is not [a-z][a-z0-9-]*"},
		{[]string{"addr", "--name=a/b"}, "is not [a-z][a-z0-9-]*"},
	} {
		opts, err := docopt.ParseArgs(usage, tc.args, "")
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if err := run(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
	// A name of 46 characters passes the check
	opts, _ := docopt.ParseArgs(usage, []string{"down", "--name=" + long[1:]}, "")
	if err := run(opts); err != nil && strings.Contains(err.Error(), "is not [a-z]") {
		t.Errorf("Name of 46 characters refused: %v", err)
	}
}

// The sandboxes of a uid: its dirs, by name (its default launcher and named ones, not another uid or the pins of
// sandbox-uplink), and its primaries without a dir
func TestSandboxCount(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"1000", "1000-work", "1000-a-b", "10000", "10001-x", "100", "lock-1000"} {
		os.Mkdir(filepath.Join(dir, d), 0o700)
	}
	os.WriteFile(filepath.Join(dir, "1000-file"), nil, 0o600)
	// uid 1000 is rs in base 36, 10000 7ps
	devices := []string{primaryName("sbx-", 1000, "work"), "sbx-rs-0123abcd", "sbx-rsx-0123abc", "sbx-7ps-0123abc", "eth0"}
	if n, err := sandboxCount(dir, 1000, devices); err != nil || n != 4 {
		t.Errorf("sandboxCount = %d, %v, want 4", n, err)
	}
}

// lock excludes a second holder of the same uid until it's released (the per-uid limit of up relies on it)
func TestLock(t *testing.T) {
	dir, uid := t.TempDir(), os.Getuid()
	unlock, err := lock(dir, uid)
	if err != nil {
		t.Fatal(err)
	}
	fd := flock(t, filepath.Join(dir, fmt.Sprint("lock-", uid)), unix.LOCK_NB)
	if fd >= 0 {
		t.Fatal("a second lock was taken while the first was held")
	}
	unlock()
	if flock(t, filepath.Join(dir, fmt.Sprint("lock-", uid)), unix.LOCK_NB) < 0 {
		t.Fatal("not released")
	}
	// The lock dir of a uid belongs to it: a dir of uid named for another isn't taken
	if _, err := lock(dir, uid+1); err == nil || !strings.Contains(err.Error(), "is not a dir of uid") {
		t.Errorf("lock of another uid: %v", err)
	}
}

// A stopped up of another user, holding its lock (and pinDir, the lock of all users once), holds back no other user
func TestLockPerUID(t *testing.T) {
	dir, uid := t.TempDir(), os.Getuid()
	os.Mkdir(filepath.Join(dir, fmt.Sprint("lock-", uid+1)), 0o700)
	for _, d := range []string{dir, filepath.Join(dir, fmt.Sprint("lock-", uid+1))} {
		if flock(t, d, 0) < 0 {
			t.Fatal("hold", d)
		}
	}
	done := make(chan error, 1)
	go func() {
		unlock, err := lock(dir, uid)
		if err == nil {
			unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock of another uid held up")
	}
}

// flock takes an exclusive flock on dir, held until the test ends; -1 when how has LOCK_NB and it's held
func flock(t *testing.T, dir string, how int) int {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	if err := unix.Flock(fd, unix.LOCK_EX|how); err != nil {
		return -1
	}
	return fd
}
