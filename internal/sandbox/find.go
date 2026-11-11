// Package sandbox finds a launcher's running sandbox and the app in it, as the launcher and the permissions broker
// both need them
package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/proc"
)

// ErrAmbiguous: more than one process sits at the app's pid, at the app's level
var ErrAmbiguous = errors.New("Several processes in the sandbox sit at the app's pid")

// Find returns the running sandbox of appID and a pidfd of it: the outer bwrap's child, which the nixpak instance
// whose info names appID reports in its bwrapinfo.json. A stale instance directory names a pid another process may
// hold by now, in a nested pid namespace or another sandbox: the pid must still be in the namespaces bwrap reported,
// and its parent, the outer bwrap, a process of ours. The pidfd, taken first, keeps the answers about the one process
func Find(runtime, appID string) (pid, pidfd int, err error) {
	dirs, _ := filepath.Glob(filepath.Join(runtime, ".flatpak", "nixpak-app-*"))
	for _, d := range dirs {
		meta, err := os.ReadFile(filepath.Join(d, "info"))
		if err != nil || !bytes.Contains(append([]byte("\n"), meta...), []byte("\nname="+appID+"\n")) {
			continue
		}
		info, err := readBwrapInfo(filepath.Join(d, "bwrapinfo.json"))
		if err != nil || proc.SameNs(info.ChildPid, "mnt") {
			continue
		}
		fd, err := unix.PidfdOpen(info.ChildPid, 0)
		if err != nil {
			continue
		}
		if !info.names(info.ChildPid) || !parentIsOurs(info.ChildPid) {
			unix.Close(fd)
			continue
		}
		return info.ChildPid, fd, nil
	}
	return 0, -1, errors.New("Not running")
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
	return proc.NsIno(pid, "mnt") == i.Mnt && proc.NsIno(pid, "pid") == i.Pid
}

// parentIsOurs reports whether pid's parent is in our user namespace
func parentIsOurs(pid int) bool {
	ppid, _, err := proc.Parent(pid)
	return err == nil && ppid > 0 && proc.SameNs(ppid, "user")
}

// AppPid returns the app's main process below the sandbox's init at sandboxPid: the one at appPid in the FHS env's
// pid ns, one level below the sandbox's (see app-pid.sh). The level counts: the sandbox can put a process at appPid
// in a pid ns of its own further down, nearer to its init in the tree than the app. Two at that level (a pid ns it
// made next to the FHS env's) leave the app unknown: ErrAmbiguous. Re-entries come in through nsenter, so they aren't
// the init's descendants
func AppPid(sandboxPid, appPid int) (int, error) {
	top, err := nsPids(sandboxPid)
	if err != nil {
		return 0, err
	}
	level := len(top) + 1
	var found []int
	for queue := []int{sandboxPid}; len(queue) > 0; queue = queue[1:] {
		p := queue[0]
		ns, err := nsPids(p)
		if err != nil {
			continue
		}
		if len(ns) == level && ns[level-1] == appPid {
			found = append(found, p)
		}
		queue = append(queue, children(p)...)
	}
	switch len(found) {
	case 0:
		return 0, errors.New("The sandbox has no app")
	case 1:
		return found[0], nil
	}
	return 0, fmt.Errorf("%w %d: %v", ErrAmbiguous, appPid, found)
}

// nsPids is pid's NSpid line: its pid in each pid namespace it is in, outermost first
func nsPids(pid int) ([]int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "NSpid:"); ok {
			var pids []int
			for _, f := range strings.Fields(v) {
				n, err := strconv.Atoi(f)
				if err != nil {
					return nil, err
				}
				pids = append(pids, n)
			}
			return pids, nil
		}
	}
	return nil, fmt.Errorf("No NSpid for %d", pid)
}

func children(pid int) []int {
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(f); err == nil {
			pids = append(pids, n)
		}
	}
	return pids
}
