package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// attach clones root/rel, the file expect names if set, and mounts it at name in the grant directory in M1.
// Returns the source as resolved
func (s *sandbox) attach(root, rel string, ro bool, expect string, denied []string, dir grantDir, name string) (string, error) {
	if err := s.check(); err != nil {
		return "", err
	}
	self, err := executable()
	if err != nil {
		return "", fmt.Errorf("Find own executable: %w", err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	ours, theirs := os.NewFile(uintptr(pair[0]), "clone"), os.NewFile(uintptr(pair[1]), "clone-helper")
	defer ours.Close()
	mode := "rw"
	if ro {
		mode = "ro"
	}
	// The sandbox's uts namespace too, though the helper has no use for it: with --user alone, nsenter (util-linux
	// 2.42.3) enters the user namespace in its first pass, which then leaves --keep-caps without effect
	args := []string{"--user=/proc/self/fd/3", "--uts=/proc/self/fd/5", "--preserve-credentials", "--keep-caps", "--",
		self, "clone-tree"}
	if expect != "" {
		args = append(args, "--expect="+expect)
	}
	clone := exec.Command(nsenter, append(append(args, root, rel, mode), denied...)...)
	clone.ExtraFiles = []*os.File{s.userns, theirs, s.uts}
	out, err := clone.CombinedOutput()
	theirs.Close()
	if err != nil {
		return "", fmt.Errorf("Clone %s: %s", filepath.Join(root, rel), strings.TrimSpace(string(out)))
	}
	tree, resolvedPath, err := recvTree(int(ours.Fd()))
	if err != nil {
		return "", err
	}
	defer tree.Close()
	if err := s.inM1(dir, []*os.File{tree}, "move-tree", name); err != nil {
		return "", fmt.Errorf("Mount %s/%s: %w", dir.path, name, err)
	}
	return resolvedPath, nil
}

func recvTree(sock int) (*os.File, string, error) {
	buf := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return nil, "", fmt.Errorf("Receive the cloned tree: %w", err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, "", errors.New("The clone helper sent no tree")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		return nil, "", errors.New("The clone helper sent no tree")
	}
	return os.NewFile(uintptr(fds[0]), "tree"), string(buf[:n]), nil
}

// cloneTree is the clone-tree helper, run in the user namespace owning the sandbox's mount namespace. In a mount
// namespace of its own, copied from ours (open_tree only clones from the caller's own), it opens root without
// following links, rel beneath it without following links or crossing mounts, refuses what is a denied directory,
// lies beneath one or holds one, and clones that one mount, read-only if asked and without devices or setuid for a
// directory. With expect (device:inode), the source must be that file. It sends the tree's fd and the path it resolved
// to on fd 4
func cloneTree(root, rel, mode, expect string, denied []string) error {
	// The new mount namespace is this thread's, so everything below stays on it; the process ends after
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_FS | unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("Unshare a mount namespace: %w (%s)", err, credentials())
	}
	fd, rootFd, err := openSource(root, rel)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	defer unix.Close(rootFd)
	// What the user was asked about, if they were: another directory renamed into its path since isn't granted
	if expect != "" {
		if id, err := idOf(fd); err != nil || id.String() != expect {
			return fmt.Errorf("%s isn't the folder you were asked about any more: it was renamed or replaced", rel)
		}
	}
	if err := checkIdentity(fd, rootFd, denied); err != nil {
		return err
	}
	// Not AT_RECURSIVE: a mount beneath it would come along unchecked. In this namespace, copied into a less
	// privileged one, every mount is locked, so a source with mounts beneath fails here
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return fmt.Errorf("Clone %s (it mustn't have mounts beneath it): %w", rel, err)
	}
	defer unix.Close(tree)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	var attr uint64
	if mode == "ro" {
		attr |= unix.MOUNT_ATTR_RDONLY
	}
	if st.Mode&unix.S_IFMT == unix.S_IFDIR {
		attr |= unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOSUID
	}
	if attr != 0 {
		if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: attr}); err != nil {
			return fmt.Errorf("Set the attributes of %s: %w", rel, err)
		}
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	if err := unix.Sendmsg(4, []byte(path), unix.UnixRights(tree), nil, 0); err != nil {
		return fmt.Errorf("Send the tree: %w", err)
	}
	return nil
}

// credentials describes this process's ids and capabilities, for errors where they're the likely cause
func credentials() string {
	status, _ := os.ReadFile("/proc/self/status")
	var parts []string
	for _, line := range strings.Split(string(status), "\n") {
		for _, k := range []string{"Uid:", "CapPrm:", "CapEff:", "CapAmb:", "NoNewPrivs:"} {
			if strings.HasPrefix(line, k) {
				parts = append(parts, strings.Join(strings.Fields(line), " "))
			}
		}
	}
	bits, _ := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	user, _ := os.Readlink("/proc/self/ns/user")
	return strings.Join(append(parts, fmt.Sprintf("securebits %#x", bits), user), ", ")
}
