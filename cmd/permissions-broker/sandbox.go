package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/mountinfo"
	"github.com/orbit-online/agent-sandbox/internal/proc"
)

// The running sandbox: the outer bwrap's child, which nixpak's bwrapinfo.json names, in M1. Its user (U1), mount
// (M1) and uts namespaces are pinned when it's found: the helpers join those, never what pid shows later, which code
// running as bwrap's init could change with unshare
type sandbox struct {
	pid              int
	pidfd            int
	userns, mnt, uts *os.File
}

// findSandbox waits up to a minute for the launcher's sandbox, found as claude-desktop.sh's sandbox_pid finds it: the
// nixpak instance whose info names appID, and whose child-pid is in a mount namespace other than ours
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
	dirs, _ := filepath.Glob(filepath.Join(runtime, ".flatpak", "nixpak-app-*"))
	for _, d := range dirs {
		meta, err := os.ReadFile(filepath.Join(d, "info"))
		if err != nil || !bytes.Contains(append([]byte("\n"), meta...), []byte("\nname="+appID+"\n")) {
			continue
		}
		info, err := readBwrapInfo(filepath.Join(d, "bwrapinfo.json"))
		if err != nil || sameNs(info.ChildPid, "mnt") {
			continue
		}
		fd, err := unix.PidfdOpen(info.ChildPid, 0)
		if err != nil {
			continue
		}
		// A stale instance directory names a pid another process may hold by now, in a nested pid namespace or another
		// sandbox: the pid must still be in the namespaces bwrap reported, and its parent, the outer bwrap, a process
		// of ours. The pidfd, taken first, keeps the answers about the one process
		if !info.names(info.ChildPid) || !parentIsOurs(info.ChildPid) {
			unix.Close(fd)
			continue
		}
		sb, err := pinSandbox(info.ChildPid, fd)
		if err != nil {
			unix.Close(fd)
			continue
		}
		return sb, nil
	}
	return nil, errors.New("Not running")
}

// What bwrap's --info-fd wrote: its child's pid and the inodes of the namespaces it made
type bwrapInfo struct {
	ChildPid int    `json:"child-pid"`
	Mnt      uint64 `json:"mnt-namespace"`
	Pid      uint64 `json:"pid-namespace"`
}

func readBwrapInfo(path string) (bwrapInfo, error) {
	var info bwrapInfo
	data, err := os.ReadFile(path)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(data, &info); err != nil || info.ChildPid <= 0 || info.Mnt == 0 || info.Pid == 0 {
		return info, fmt.Errorf("No child-pid and namespaces in %s", path)
	}
	return info, nil
}

// names reports whether pid is in the mount and pid namespaces bwrap made
func (i bwrapInfo) names(pid int) bool {
	return nsIno(pid, "mnt") == i.Mnt && nsIno(pid, "pid") == i.Pid
}

func nsIno(pid int, kind string) uint64 {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &st) != nil {
		return 0
	}
	return st.Ino
}

// parentIsOurs reports whether pid's parent is in our user namespace
func parentIsOurs(pid int) bool {
	ppid, _, err := parent(pid)
	return err == nil && ppid > 0 && sameNs(ppid, "user")
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

// check refuses when the sandbox ended or its pid is no longer in the namespaces pinned when it was found
func (s *sandbox) check() error {
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

// mountinfo reads the mount table of the sandbox's pinned mount namespace: a /proc/<pid>/mountinfo opened while pid
// is checked to be in it, before and after (the file shows the namespace the task had at the open)
func (s *sandbox) mountinfo() ([]mountinfo.Line, error) {
	if err := s.check(); err != nil {
		return nil, err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", s.pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := s.check(); err != nil {
		return nil, err
	}
	return mountinfo.Parse(f)
}

// sameNs reports whether pid is in our namespace of the kind (mnt, user), false when it can't tell
func sameNs(pid int, kind string) bool {
	var a, b unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &a) != nil || unix.Stat("/proc/self/ns/"+kind, &b) != nil {
		return false
	}
	return a.Ino == b.Ino && a.Dev == b.Dev
}

// alive reports whether the sandbox still runs: a pidfd turns readable when its process exits
func (s *sandbox) alive() bool { return proc.Alive(s.pidfd) }

// parent returns pid's parent and whether pid is the init of its pid namespace (its innermost NSpid is 1)
func parent(pid int) (int, bool, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false, fmt.Errorf("Read status of %d: %w", pid, err)
	}
	ppid, nsInit := 0, false
	for _, line := range strings.Split(string(data), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch {
		case k == "PPid" && len(f) == 1:
			ppid, _ = strconv.Atoi(f[0])
		case k == "NSpid" && len(f) > 0:
			nsInit = f[len(f)-1] == "1"
		}
	}
	return ppid, nsInit, nil
}
