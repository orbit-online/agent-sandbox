package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mountinfo"
	"github.com/orbit-online/agent-sandbox/internal/proc"
	sbx "github.com/orbit-online/agent-sandbox/internal/sandbox"
)

// The running sandbox: the outer bwrap's child, which nixpak's bwrapinfo.json names, in M1. Its user (U1), mount
// (M1) and uts namespaces are pinned when it's found: the helpers join those, never what pid shows later, which code
// running as bwrap's init could change with unshare
type sandbox struct {
	pid              int
	pidfd            int
	userns, mnt, uts *os.File
}

// findSandbox waits up to a minute for the launcher's sandbox (sandbox.Find), pinned
func findSandbox(appID string) (*sandbox, error) {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	for range 300 {
		if sb, err := lookupSandbox(runtime, appID); err == nil {
			return sb, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("No running sandbox for %s", appID)
}

func lookupSandbox(runtime, appID string) (*sandbox, error) {
	pid, fd, err := sbx.Find(runtime, appID)
	if err != nil {
		return nil, err
	}
	sb, err := pinSandbox(pid, fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return sb, nil
}

// pinSandbox opens the namespaces of the sandbox at pid: its mount namespace, the user namespace owning it, which
// must be pid's own and a child of ours, and its uts namespace. pidfd tells that pid named the process throughout
func pinSandbox(pid, pidfd int) (*sandbox, error) {
	s := &sandbox{pid: pid, pidfd: pidfd}
	var err error
	if s.mnt, err = os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid)); err != nil {
		return nil, fmt.Errorf("Open the sandbox's mount namespace: %w", err)
	}
	if s.uts, err = os.Open(fmt.Sprintf("/proc/%d/ns/uts", pid)); err != nil {
		s.close()
		return nil, fmt.Errorf("Open the sandbox's uts namespace: %w", err)
	}
	ownerFd, err := unix.IoctlRetInt(int(s.mnt.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("Find the owner of the sandbox's mount namespace: %w", err)
	}
	s.userns = os.NewFile(uintptr(ownerFd), "userns")
	parentFd, err := unix.IoctlRetInt(ownerFd, unix.NS_GET_PARENT)
	if err != nil {
		s.close()
		return nil, fmt.Errorf("Find the parent of the sandbox's user namespace: %w", err)
	}
	parentNs := os.NewFile(uintptr(parentFd), "userns")
	defer parentNs.Close()
	switch {
	case !sameFile(parentNs, "/proc/self/ns/user"):
		err = errors.New("The sandbox's user namespace isn't a child of ours")
	case !sameFile(s.userns, fmt.Sprintf("/proc/%d/ns/user", pid)):
		err = errors.New("The sandbox's process isn't in the user namespace owning its mount namespace")
	case !proc.Alive(pidfd):
		err = errors.New("The sandbox ended")
	}
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

func (s *sandbox) close() {
	for _, f := range []*os.File{s.userns, s.mnt, s.uts} {
		if f != nil {
			f.Close()
		}
	}
}

// sameFile reports whether f is the file at path, by device and inode
func sameFile(f *os.File, path string) bool {
	var a, b unix.Stat_t
	if unix.Fstat(int(f.Fd()), &a) != nil || unix.Stat(path, &b) != nil {
		return false
	}
	return a.Dev == b.Dev && a.Ino == b.Ino
}

// Check refuses when the sandbox ended or its pid is no longer in the namespaces pinned when it was found
func (s *sandbox) Check() error {
	if s.mnt == nil {
		return errors.New("The sandbox's namespaces aren't known")
	}
	if !sameFile(s.mnt, fmt.Sprintf("/proc/%d/ns/mnt", s.pid)) || !sameFile(s.userns, fmt.Sprintf("/proc/%d/ns/user", s.pid)) {
		if !s.alive() {
			return errors.New("The sandbox ended")
		}
		return errors.New("The sandbox's process left the namespaces it started in")
	}
	if !s.alive() {
		return errors.New("The sandbox ended")
	}
	return nil
}

// Mountinfo reads the mount table of the sandbox's pinned mount namespace: a /proc/<pid>/mountinfo opened while pid
// is checked to be in it, before and after (the file shows the namespace the task had at the open)
func (s *sandbox) Mountinfo() ([]mountinfo.Line, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", s.pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := s.Check(); err != nil {
		return nil, err
	}
	return mountinfo.Parse(f)
}

// sameNs reports whether pid is in our namespace of the kind (mnt, user), false when it can't tell
// Namespaces are the sandbox's pinned namespaces: the user namespace owning its mount namespace, the mount namespace
// and its uts namespace
func (s *sandbox) Namespaces() (user, mnt, uts *os.File) { return s.userns, s.mnt, s.uts }

// alive reports whether the sandbox still runs: a pidfd turns readable when its process exits
func (s *sandbox) alive() bool { return proc.Alive(s.pidfd) }
