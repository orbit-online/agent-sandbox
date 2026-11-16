// Package caller checks who runs a privileged helper of the sandbox (netns-netkit, sandbox-hooks) and what it names:
// the caller a human, a launcher name, a network namespace of the caller's below its own user namespace
package caller

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// What a launcher name may be (the assertion of the module), so it makes a pin name
var LauncherName = regexp.MustCompile(`^([a-z][a-z0-9-]{0,45})?$`)

// Human refuses callers outside group users: the setuid and setgid wrappers (netns-netkit, sandbox-hooks) take the
// group of the file, so the group can't limit who runs them. Whoever runs netns-netkit gives their own namespaces a
// network outside the host firewall
func Human() error {
	g, err := user.LookupGroup("users")
	if err != nil {
		return fmt.Errorf("Look up group users: %w", err)
	}
	gid, _ := strconv.Atoi(g.Gid)
	groups, err := unix.Getgroups()
	if err != nil {
		return fmt.Errorf("Read the groups of the caller: %w", err)
	}
	if unix.Getgid() != gid && !slices.Contains(groups, gid) {
		return errors.New("Only members of group users may run " + filepath.Base(os.Args[0]))
	}
	return nil
}
