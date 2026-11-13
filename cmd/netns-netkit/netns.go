package main

import (
	"fmt"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Opens the network namespace of pid after checking that the caller, of uid in user namespace ownUserns (a path),
// may give it a netkit pair
func openNetns(pid, uid int, ownUserns string) (int, error) {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return -1, fmt.Errorf("Open pidfd for %d: %w", pid, err)
	}
	defer unix.Close(pidfd)
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid), &st); err != nil {
		return -1, fmt.Errorf("Stat process %d: %w", pid, err)
	}
	if int(st.Uid) != uid {
		return -1, fmt.Errorf("Process %d belongs to uid %d, not %d", pid, st.Uid, uid)
	}
	netnsFd, err := openAsCaller("/proc/" + strconv.Itoa(pid) + "/ns/net")
	if err != nil {
		return -1, fmt.Errorf("Open network namespace of %d: %w", pid, err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(netnsFd)
		}
	}()
	// The pidfd outlives a recycled pid, so a successful signal 0 means the checks above were about this process
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return -1, fmt.Errorf("Process %d exited during checks: %w", pid, err)
	}
	var own unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &own); err != nil {
		return -1, fmt.Errorf("Stat own network namespace: %w", err)
	}
	if err := unix.Fstat(netnsFd, &st); err != nil {
		return -1, fmt.Errorf("Stat network namespace of %d: %w", pid, err)
	}
	if st.Dev == own.Dev && st.Ino == own.Ino {
		return -1, fmt.Errorf("Process %d shares the caller's network namespace", pid)
	}
	usernsFd, err := unix.IoctlRetInt(netnsFd, unix.NS_GET_USERNS)
	if err != nil {
		return -1, fmt.Errorf("Get user namespace owning the network namespace of %d: %w", pid, err)
	}
	defer unix.Close(usernsFd)
	if err := ownedBelow(usernsFd, ownUserns, uid); err != nil {
		return -1, fmt.Errorf("Network namespace of %d %w", pid, err)
	}
	ok = true
	return netnsFd, nil
}

// openAsCaller opens path with the caller's own gid as the filesystem gid: the wrapper is setgid sandbox-uplink, and
// the kernel's ptrace check on /proc/<pid>/ns/* compares that gid with the target's. fsgid is per thread
func openAsCaller(path string) (int, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	prev, err := unix.SetfsgidRetGid(unix.Getgid())
	if err != nil {
		return -1, err
	}
	defer unix.Setfsgid(prev)
	return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

// Checks that the user namespace usernsFd lies below ownUserns, and that the one right below ownUserns on the way
// there is owned by uid. By the owner rule that uid then holds every capability in it and in everything below, whoever
// owns those: the immediate owner alone would pass a user namespace of the caller's below one a privileged process
// made and mapped the caller's uid into
func ownedBelow(usernsFd int, ownUserns string, uid int) error {
	var own unix.Stat_t
	if err := unix.Stat(ownUserns, &own); err != nil {
		return fmt.Errorf("can't be checked: stat own user namespace: %w", err)
	}
	fd, err := unix.Dup(usernsFd)
	if err != nil {
		return fmt.Errorf("can't be checked: %w", err)
	}
	defer func() { unix.Close(fd) }()
	if same(fd, own) {
		return fmt.Errorf("is owned by the caller's own user namespace")
	}
	// The kernel nests at most 32 user namespaces
	for range 33 {
		parent, err := unix.IoctlRetInt(fd, unix.NS_GET_PARENT)
		if err != nil {
			// EPERM: fd is the caller's user namespace or above it, which the walk passed without meeting the caller's
			return fmt.Errorf("isn't below the caller's user namespace: %w", err)
		}
		if same(parent, own) {
			unix.Close(parent)
			var owner uint32
			if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.NS_GET_OWNER_UID, uintptr(unsafe.Pointer(&owner))); errno != 0 {
				return fmt.Errorf("can't be checked: get owner of user namespace: %w", errno)
			}
			if int(owner) != uid {
				return fmt.Errorf("is owned by uid %d, not %d", owner, uid)
			}
			return nil
		}
		unix.Close(fd)
		fd = parent
	}
	return fmt.Errorf("is nested deeper than the kernel allows")
}

// Whether fd is the namespace st describes
func same(fd int, st unix.Stat_t) bool {
	var fst unix.Stat_t
	return unix.Fstat(fd, &fst) == nil && fst.Dev == st.Dev && fst.Ino == st.Ino
}
