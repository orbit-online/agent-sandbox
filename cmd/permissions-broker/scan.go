package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The holders' scan: which processes in the sandbox still reach an attach grant's files after its detach, which ends
// its mounts in every namespace it propagated to, but not what's open on them, nor copies made elsewhere

// A process in the sandbox holding files, mappings, its working directory or a mount of its own of a grant. Start
// (its start time) tells it from a later process with the same pid. Possible: it holds a file of the grant's
// filesystem on a mount no mountinfo shows, which the daemon can't tie to the grant's files
type holder struct {
	Pid      int    `json:"pid"`
	Comm     string `json:"comm"`
	Start    uint64 `json:"start"`
	Possible bool   `json:"possible,omitempty"`
}

// How long the holders' scan may take: the sandbox decides how many processes and files there are
var holdersTimeout = 10 * time.Second

// Called as the scan starts, for the tests
var scanStarts = func() {}

// tasks lists the /proc directories of pid's threads. Each may have a working directory, root, file table and mount
// namespace of its own (unshare with CLONE_FS, CLONE_FILES or CLONE_NEWNS on one thread), which the thread group
// leader's entries don't show
func tasks(pid int) []string {
	entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	dirs := make([]string, 0, len(entries))
	for _, e := range entries {
		dirs = append(dirs, fmt.Sprintf("/proc/%d/task/%s", pid, e.Name()))
	}
	return dirs
}

// mntNs is the mount namespace of the task or process at dir in /proc, by inode
func mntNs(dir string) (uint64, bool) {
	var st unix.Stat_t
	if unix.Stat(dir+"/ns/mnt", &st) != nil {
		return 0, false
	}
	return st.Ino, true
}

// The mounts the sandbox's processes see, from every mount namespace one of their threads is in
type mountView struct {
	m        *grantMount
	deadline time.Time
	// Every mount in a mountinfo read, the daemon's own included: a file on none of them is on a detached mount (a
	// lazy unmount's, open_tree's), or in a namespace no process is in
	visible map[uint64]bool
	// The grant's mounts, and mounts of its filesystem and root a process made elsewhere; the namespaces (by inode)
	// holding one of the latter
	copies, rebinds map[uint64]bool
	// contains' answers, by path and inode
	tried map[string]bool
}

// viewMounts reads the mountinfo of each mount namespace of the processes' threads once
func viewMounts(pids []int, m *grantMount, deadline time.Time) *mountView {
	v := &mountView{m: m, deadline: deadline, visible: map[uint64]bool{}, copies: map[uint64]bool{m.id: true},
		rebinds: map[uint64]bool{}, tried: map[string]bool{}}
	for _, l := range readMountinfo("/proc/self/mountinfo") {
		v.visible[l.id] = true
	}
	seen := map[uint64]bool{}
	for _, pid := range pids {
		if time.Now().After(deadline) {
			break
		}
		for _, task := range tasks(pid) {
			ns, ok := mntNs(task)
			if !ok || seen[ns] {
				continue
			}
			seen[ns] = true
			for _, l := range readMountinfo(task + "/mountinfo") {
				v.visible[l.id] = true
				if m.copyOf(l) || mountsOf([]mountLine{l}, m.dev, m.root) {
					v.copies[l.id] = true
					v.rebinds[ns] = true
				}
			}
		}
	}
	return v
}

// holdersAfter lists, after the detach, the processes in the sandbox still holding the grant: a working directory,
// root or open file on its mounts (by mount id, which an open file keeps) or on a detached mount of its files, or a
// mount of their own of the same filesystem and root, which a process can make in a mount namespace of its own and the
// detach doesn't reach. Every thread counts. Best effort: an fd in flight in an SCM_RIGHTS message or registered with
// io_uring shows nowhere in /proc, and keeps the grant readable until it's closed or the sandbox ends
func (s *sandbox) holdersAfter(m *grantMount) []holder {
	scanStarts()
	deadline := time.Now().Add(holdersTimeout)
	pids := s.members()
	v := viewMounts(pids, m, deadline)
	var hs []holder
	for _, pid := range pids {
		if time.Now().After(deadline) {
			slog.Warn("Holders' scan cut short", "after", holdersTimeout)
			break
		}
		held, possible := v.holds(pid)
		if !held {
			held = holdsMapping(pid, v.copies)
		}
		if held || possible {
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if start, ok := startTime(pid); ok {
				hs = append(hs, holder{Pid: pid, Comm: strings.TrimSpace(string(comm)), Start: start, Possible: !held})
			}
		}
	}
	return hs
}

// holds reports whether a thread of pid has a mount of the grant's in its mount namespace, or its working directory,
// root or an open file on the grant; or possibly, on a detached mount of its filesystem
func (v *mountView) holds(pid int) (held, possible bool) {
	for _, task := range tasks(pid) {
		if ns, ok := mntNs(task); ok && v.rebinds[ns] {
			return true, false
		}
		paths := []string{task + "/cwd", task + "/root"}
		entries, _ := os.ReadDir(task + "/fd")
		for _, e := range entries {
			paths = append(paths, task+"/fd/"+e.Name())
		}
		for _, p := range paths {
			h, maybe := v.file(p)
			if h {
				return true, false
			}
			possible = possible || maybe
		}
	}
	return false, possible
}

// file reports whether path (a magic link in /proc) leads to the grant: on one of its mounts, or on a mount no
// mountinfo shows, of the grant's filesystem, where /proc names one of the grant's files; possibly, if it names none
func (v *mountView) file(path string) (held, possible bool) {
	var stx unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID|unix.STATX_INO, &stx) != nil ||
		stx.Mask&unix.STATX_MNT_ID == 0 {
		return false, false
	}
	if v.copies[stx.Mnt_id] {
		return true, false
	}
	if v.visible[stx.Mnt_id] || unix.Mkdev(stx.Dev_major, stx.Dev_minor) != v.m.srcDev {
		return false, false
	}
	link, err := os.Readlink(path)
	if err == nil && v.contains(link, stx.Ino) {
		return true, false
	}
	return false, true
}

// contains reports whether path, as /proc names a file (on a detached mount, relative to its root; on a copy, below
// its mount point), names the grant's file ino: some tail of it, resolved beneath the grant's tree without links, is
// that inode. Not a file deleted since
func (v *mountView) contains(path string, ino uint64) bool {
	if strings.HasSuffix(path, " (deleted)") {
		return false
	}
	key := fmt.Sprintf("%d %s", ino, path)
	if known, ok := v.tried[key]; ok {
		return known
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	found := false
	for i := 0; i <= len(parts) && !found && time.Now().Before(v.deadline); i++ {
		st, ok := v.inTree(strings.Join(parts[i:], "/"))
		found = ok && st.Ino == ino && st.Dev == v.m.srcDev
	}
	v.tried[key] = found
	return found
}

// inTree stats rel beneath the grant's tree, without following links or leaving it
func (v *mountView) inTree(rel string) (unix.Stat_t, bool) {
	var st unix.Stat_t
	if rel == "" {
		rel = "."
	}
	fd, err := unix.Openat2(int(v.m.tree.Fd()), rel, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return st, false
	}
	defer unix.Close(fd)
	return st, unix.Fstat(fd, &st) == nil
}

// holdsMapping reports whether pid maps a file on one of the grant's mounts, in any namespace: its threads share
// their mappings
func holdsMapping(pid int, all map[uint64]bool) bool {
	entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/map_files", pid))
	for _, e := range entries {
		var stx unix.Statx_t
		path := fmt.Sprintf("/proc/%d/map_files/%s", pid, e.Name())
		if unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stx) == nil && all[stx.Mnt_id] {
			return true
		}
	}
	return false
}
