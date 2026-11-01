package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// The helpers that act in the sandbox's mount namespace M1: make-shared, move-tree and detach. A path there shows what
// the sandbox wants: from a nested namespace, after pivot_root and a lazy unmount of the old root, it can rename a
// directory that is a mountpoint in M1 (/nix/store, /run/permissions), as the kernel refuses that only for mounts in
// the caller's own namespace, and put its own in the old name's place. So no helper is exec'd in M1: nsenter joins the
// user namespace owning it on the host's mounts, and execs the daemon's own binary there; the helper then joins M1
// itself (fd 4) on a thread of its own, and resolves nothing in it but the grant directory: without following links,
// and checked to be the directory the host bound there, by device and inode

// The grant directory: its path where the sandbox sees it, and the device and inode of the host's directory
type grantDir struct{ path, id string }

func grantDirOf(cfg config) (grantDir, error) {
	var st unix.Stat_t
	if err := unix.Lstat(cfg.GrantDir, &st); err != nil {
		return grantDir{}, fmt.Errorf("The grant directory: %w", err)
	}
	return grantDir{path: cfg.SandboxGrantDir, id: fmt.Sprintf("%d:%d", st.Dev, st.Ino)}, nil
}

// Overridden by the tests, to run a copy of the test binary as the helper
var executable = os.Executable

// inM1 runs a helper in M1 with every capability in the user namespace owning it, the files extra from fd 6 on. With
// --user alone, nsenter (util-linux 2.42.3) enters the user namespace in its first pass, which then leaves --keep-caps
// without effect: hence the sandbox's uts namespace too, which the helpers have no use for
func (s *sandbox) inM1(dir grantDir, extra []*os.File, helper string, args ...string) error {
	if err := s.check(); err != nil {
		return err
	}
	self, err := executable()
	if err != nil {
		return fmt.Errorf("Find own executable: %w", err)
	}
	cmd := exec.Command(nsenter, append([]string{"--user=/proc/self/fd/3", "--uts=/proc/self/fd/5",
		"--preserve-credentials", "--keep-caps", "--", self, helper, dir.path, dir.id}, args...)...)
	cmd.ExtraFiles = append([]*os.File{s.userns, s.mnt, s.uts}, extra...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

// share makes the grant directory a shared mount in M1
func (s *sandbox) share(dir grantDir) error {
	if err := s.inM1(dir, nil, "make-shared"); err != nil {
		return fmt.Errorf("Make %s shared: %w", dir.path, err)
	}
	return nil
}

// detach unmounts grant mounts, by their names in the grant directory, in M1. The daemon reads which from the host:
// in there /proc is the sandbox's, where the helper isn't
func (s *sandbox) detach(dir grantDir, names ...string) error {
	if len(names) == 0 {
		return nil
	}
	if err := s.inM1(dir, nil, "detach", names...); err != nil {
		return fmt.Errorf("Unmount %s: %w", strings.Join(names, ", "), err)
	}
	return nil
}

// detachBelow unmounts every mount in the grant directory in M1: what an earlier daemon left. Those on top of one go
// with it
func (s *sandbox) detachBelow(dir grantDir) error {
	lines, err := s.mountinfo()
	if err != nil {
		return err
	}
	var names []string
	for _, p := range mountsBelow(lines, dir.path) {
		name, _, _ := strings.Cut(strings.TrimPrefix(p, dir.path+"/"), "/")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return s.detach(dir, names...)
}

// enterM1 is the helpers' side: it joins the mount namespace on fd 4 on this thread alone (Go's threads share their
// filesystem context, which setns refuses), and opens the grant directory there as described above
func enterM1(path, id string) (int, error) {
	// The process ends with the helper, on this thread
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return -1, fmt.Errorf("Unshare the filesystem context: %w", err)
	}
	if err := unix.Setns(4, unix.CLONE_NEWNS); err != nil {
		return -1, fmt.Errorf("Join the sandbox's mount namespace: %w (%s)", err, credentials())
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return -1, fmt.Errorf("Open %s in the sandbox without links: %w", path, err)
	}
	var st unix.Stat_t
	var stx unix.Statx_t
	if unix.Fstat(fd, &st) != nil || unix.Statx(fd, "", unix.AT_EMPTY_PATH, 0, &stx) != nil ||
		fmt.Sprintf("%d:%d", st.Dev, st.Ino) != id || stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		unix.Close(fd)
		return -1, fmt.Errorf("%s in the sandbox isn't the grant directory: it was replaced", path)
	}
	return fd, nil
}

// checkName refuses a name that isn't one entry of the grant directory
func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("%q isn't an entry of the grant directory", name)
	}
	return nil
}

// makeShared is the make-shared helper: the grant directory turns a shared mount
func makeShared(path, id string) error {
	dir, err := enterM1(path, id)
	if err != nil {
		return err
	}
	return unix.MountSetattr(dir, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Propagation: unix.MS_SHARED})
}

// moveTree is the move-tree helper: it attaches the tree on fd 6 at name in the grant directory
func moveTree(path, id, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	dir, err := enterM1(path, id)
	if err != nil {
		return err
	}
	if err := unix.MoveMount(6, "", dir, name, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("Attach at %s/%s: %w", path, name, err)
	}
	return nil
}

// detachHelper is the detach helper: it unmounts what's mounted at names in the grant directory, lazily (what's open
// on them stays open)
func detachHelper(path, id string, names []string) error {
	for _, n := range names {
		if err := checkName(n); err != nil {
			return err
		}
	}
	dir, err := enterM1(path, id)
	if err != nil {
		return err
	}
	if err := unix.Fchdir(dir); err != nil {
		return err
	}
	for _, n := range names {
		if err := unix.Unmount(n, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("Unmount %s/%s: %w", path, n, err)
		}
	}
	return nil
}
