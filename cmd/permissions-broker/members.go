package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Which processes are the sandbox's: by namespace, not by ancestry. A re-entry (claude-desktop --shell, claude://)
// joins the app's namespaces through nsenter from the host, so it and everything it starts are no descendants of the
// sandbox's pid, yet they are in U2, below U1. A process is the sandbox's when its user namespace, or the one owning
// its mount namespace, is the sandbox's pinned user namespace or below it

// nsKey identifies a namespace by its nsfs device and inode
type nsKey struct{ dev, ino uint64 }

func keyOf(fd int) (nsKey, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nsKey{}, err
	}
	return nsKey{st.Dev, st.Ino}, nil
}

// below reports whether the user namespace fd is the sandbox's or a descendant of it, walking up with NS_GET_PARENT
// until the sandbox's, or until the walk can't go further (our own user namespace, whose parent we may not open).
// Takes fd
func (s *sandbox) below(fd int, seen map[nsKey]bool) bool {
	if s.userns == nil {
		unix.Close(fd)
		return false
	}
	top, err := keyOf(int(s.userns.Fd()))
	if err != nil {
		unix.Close(fd)
		return false
	}
	var walked []nsKey
	result := false
	for {
		k, err := keyOf(fd)
		if err != nil {
			break
		}
		if known, ok := seen[k]; ok {
			result = known
			break
		}
		walked = append(walked, k)
		if k == top {
			result = true
			break
		}
		up, err := unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
		if err != nil {
			break
		}
		unix.Close(fd)
		fd = up
	}
	unix.Close(fd)
	for _, k := range walked {
		seen[k] = result
	}
	return result
}

// contains reports whether pid is the sandbox's, as of now: the caller rechecks a pidfd after, where it matters
func (s *sandbox) contains(pid int) bool { return s.containsCached(pid, map[nsKey]bool{}) }

func (s *sandbox) containsCached(pid int, seen map[nsKey]bool) bool {
	user, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	if s.below(user, seen) {
		return true
	}
	mnt, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	owner, err := unix.IoctlRetInt(mnt, unix.NS_GET_USERNS)
	unix.Close(mnt)
	if err != nil {
		return false
	}
	return s.below(owner, seen)
}

// members lists the sandbox's processes, from /proc
func (s *sandbox) members() []int {
	entries, _ := os.ReadDir("/proc")
	seen := map[nsKey]bool{}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		if s.containsCached(pid, seen) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// copied reports whether a process of the sandbox is in a copy of M1: a mount namespace owned by a user namespace
// below the sandbox's. The FHS env's bwrap (or anything else in the sandbox) made it, and a share now wouldn't reach
// it. Not one owned by the sandbox's user namespace itself: only the host has the capabilities to make those (udhcpc's,
// the clone helper's), from the host's mounts, as it has for joining U1 on the host's mounts (net-setup's ip)
func (s *sandbox) copied() (bool, error) {
	if s.mnt == nil || s.userns == nil {
		return false, errors.New("The sandbox's namespaces aren't known")
	}
	m1, err := keyOf(int(s.mnt.Fd()))
	if err != nil {
		return false, err
	}
	top, err := keyOf(int(s.userns.Fd()))
	if err != nil {
		return false, err
	}
	seen := map[nsKey]bool{}
	for _, pid := range s.members() {
		mnt, err := unix.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		key, kerr := keyOf(mnt)
		owner, oerr := unix.IoctlRetInt(mnt, unix.NS_GET_USERNS)
		unix.Close(mnt)
		if kerr != nil || oerr != nil {
			continue
		}
		if k, err := keyOf(owner); err != nil || k == top || key == m1 {
			unix.Close(owner)
			continue
		}
		if s.below(owner, seen) {
			return true, nil
		}
	}
	return false, nil
}
