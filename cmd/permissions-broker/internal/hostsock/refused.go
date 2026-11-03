// Package hostsock is what a host socket may not be, reaching one without links, and the addresses the sandbox reaches
// them at. Splicing hands a host socket the broker's standing as the host user, unsandboxed, so the broker refuses the
// sockets known to grant more than their own service: D-Bus buses (past every rule of the D-Bus proxies), the systemd
// user manager's private bus (transient units, which is running code on the host), the accessibility bus, the
// launchers' own sockets and $XDG_RUNTIME_DIR as a whole. This is a guard against the known ones: what else a socket
// gives is the config's responsibility
package hostsock

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// refusedRoots are the directories and sockets refused with everything beneath them, as segment patterns
// (filepath.Match): /proc (aliases of any path), /run/dbus, /var/run (an alias of /run), what $XDG_RUNTIME_DIR holds
// for buses and launchers, and the paths the bus address variables name
func refusedRoots(run string) []string {
	roots := []string{"/proc", "/run/dbus", "/var/run"}
	for _, own := range []string{"bus", "systemd", "at-spi", ".dbus-proxy", "dbus-*", "claude-desktop", ".flatpak",
		"agent-sandbox-permissions", "nixpak-*"} {
		roots = append(roots, run+"/"+own)
	}
	for _, env := range []string{"DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS"} {
		for _, part := range strings.Split(os.Getenv(env), ";") {
			if _, p, ok := strings.Cut(part, "path="); ok && filepath.IsAbs(p) {
				roots = append(roots, filepath.Clean(strings.Split(p, ",")[0]))
			}
		}
	}
	return roots
}

// segments splits a clean absolute path into its segments, the empty root first
func segments(path string) []string { return strings.Split(path, "/") }

// beneath reports whether the path segments p are root's or beneath them, root's segments as patterns
func beneath(p, root []string) bool {
	if len(p) < len(root) {
		return false
	}
	for i, r := range root {
		if ok, _ := filepath.Match(r, p[i]); !ok {
			return false
		}
	}
	return true
}

// runtimeDir is $XDG_RUNTIME_DIR, which a host socket can't be checked without
func runtimeDir() (string, error) {
	run := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(run) {
		return "", errors.New("$XDG_RUNTIME_DIR isn't set: no host socket can be checked")
	}
	return filepath.Clean(run), nil
}

// normal refuses a path that isn't absolute and in its clean form: no ., .. or empty segments
func normal(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%q isn't a clean absolute path (an unset variable, . or ..?)", path)
	}
	return nil
}

// Refused refuses a host socket path, as it is to be reached: without links
func Refused(path string) error {
	run, err := runtimeDir()
	if err != nil {
		return err
	}
	if err := normal(path); err != nil {
		return err
	}
	p := segments(path)
	if beneath(segments(run), p) {
		return fmt.Errorf("%s is or holds $XDG_RUNTIME_DIR", path)
	}
	for _, root := range refusedRoots(run) {
		if beneath(p, segments(root)) {
			return fmt.Errorf("%s is refused: beneath %s, a bus, /proc or the launchers' own", path, root)
		}
	}
	return nil
}

// RefusedGlob refuses an instances glob that could match a refused socket: one whose literal part (the segments before
// the *) is refused, or is a prefix of a refused root or of $XDG_RUNTIME_DIR, so that the * falls within its depth.
// Its matches are checked again one by one
func RefusedGlob(glob string) error {
	run, err := runtimeDir()
	if err != nil {
		return err
	}
	if err := normal(glob); err != nil {
		return err
	}
	p := segments(glob)
	i := 0
	for i < len(p) && !strings.Contains(p[i], "*") {
		i++
	}
	literal := p[:i]
	for _, root := range append(refusedRoots(run), run) {
		r := segments(root)
		if root != run && beneath(literal, r) || len(literal) < len(r) && beneath(literal, r[:len(literal)]) {
			return fmt.Errorf("instances %s could match beneath %s, a bus, /proc or the launchers' own", glob, root)
		}
	}
	return nil
}

// openHostSocket opens path as a socket without following a link anywhere on it (O_PATH): what's refused is checked on
// the path that is opened, and a link planted at it or above it, now or later, isn't followed
func openHostSocket(path string) (int, error) {
	if err := Refused(path); err != nil {
		return -1, err
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return -1, fmt.Errorf("Open %s without links: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		unix.Close(fd)
		return -1, fmt.Errorf("%s isn't a socket", path)
	}
	return fd, nil
}

// IsSocket reports whether path is a socket the broker would connect to
func IsSocket(path string) bool {
	fd, err := openHostSocket(path)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// Test hook: between Dial's check and its connect
var hostOpened = func() {}

// Dial connects to the host socket at path through the fd openHostSocket opened: the inode checked is the one
// connected to
func Dial(path string, timeout time.Duration) (*net.UnixConn, error) {
	fd, err := openHostSocket(path)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	hostOpened()
	conn, err := net.DialTimeout("unix", fmt.Sprintf("/proc/self/fd/%d", fd), timeout)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UnixConn), nil
}
