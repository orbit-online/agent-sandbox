package hostsock

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// An address's file name is at most this long: bound through /proc/self/fd/<fd>/, it must fit a socket path's 108
// bytes
const MaxAddrName = 80

// UnsetVariable is a variable path names that isn't set, if any
func UnsetVariable(path string) string {
	unset := ""
	os.Expand(path, func(v string) string {
		if _, ok := os.LookupEnv(v); !ok && unset == "" {
			unset = v
		}
		return ""
	})
	return unset
}

// Listen listens at rel beneath dir, making the directories between as the daemon's own. Bound through the
// directory's fd, so the address isn't held to a socket path's 108 bytes, and never unlinked by its path: the fd is
// gone by then
func Listen(dir, rel string) (*net.UnixListener, error) {
	parent := filepath.Join(dir, filepath.Dir(rel))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	dfd, err := unix.Open(parent, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	name := filepath.Base(rel)
	_ = unix.Unlinkat(dfd, name, 0)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", dfd, name), Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	return ln, nil
}

// DialPath connects to the socket at path, through its directory's fd as Listen binds
func DialPath(path string, timeout time.Duration) (*net.UnixConn, error) {
	dfd, err := unix.Open(filepath.Dir(path), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	conn, err := net.DialTimeout("unix", fmt.Sprintf("/proc/self/fd/%d/%s", dfd, filepath.Base(path)), timeout)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UnixConn), nil
}
