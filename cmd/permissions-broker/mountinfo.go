package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// A line of a mountinfo file: the mount's id, device (major:minor), root, mount point and optional fields
type mountLine struct {
	id               uint64
	dev, root, point string
	optional         []string
}

// parseMountinfo reads a mountinfo file's lines
func parseMountinfo(r io.Reader) ([]mountLine, error) {
	var lines []mountLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 7 {
			continue
		}
		id, _ := strconv.ParseUint(f[0], 10, 64)
		l := mountLine{id: id, dev: f[2], root: unescapeMountinfo(f[3]), point: unescapeMountinfo(f[4])}
		for _, opt := range f[6:] {
			if opt == "-" {
				break
			}
			l.optional = append(l.optional, opt)
		}
		lines = append(lines, l)
	}
	return lines, sc.Err()
}

// readMountinfo parses a mountinfo file by path, nil when it can't be read
func readMountinfo(path string) []mountLine {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	lines, _ := parseMountinfo(f)
	return lines
}

// mountsBelow lists the mount points strictly below dir, deepest first
func mountsBelow(lines []mountLine, dir string) []string {
	var points []string
	for _, l := range lines {
		if strings.HasPrefix(l.point, dir+"/") && !slices.Contains(points, l.point) {
			points = append(points, l.point)
		}
	}
	sort.Slice(points, func(i, j int) bool { return len(points[i]) > len(points[j]) })
	return points
}

// mountinfo escapes space, tab, newline and backslash as \ooo
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// A process in the sandbox holding files, mappings, its working directory or a mount of its own of a grant. Start
// (its start time) tells it from a later process with the same pid
type holder struct {
	Pid   int    `json:"pid"`
	Comm  string `json:"comm"`
	Start uint64 `json:"start"`
}

// How long the holders' scan may take: the sandbox decides how many processes and files there are
var holdersTimeout = 10 * time.Second

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

// An attach grant's mount in M1, found when it's attached by the tree's mount id, not by its path: the sandbox can
// rename the grant directory in M1 (models/README.md, Attacker 6). Its id, peer group, and device and root, by which
// copies of it are found, and the tree itself, which the daemon keeps open
type grantMount struct {
	id        uint64
	group     string
	dev, root string
	tree      *os.File
}

// grantMountOf finds the mount the tree (attached in M1) is in M1's mountinfo, by its mount id
func (s *sandbox) grantMountOf(tree *os.File) (*grantMount, error) {
	var stx unix.Statx_t
	if err := unix.Statx(int(tree.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil ||
		stx.Mask&unix.STATX_MNT_ID == 0 {
		return nil, fmt.Errorf("The grant's mount id: %v", err)
	}
	lines, err := s.mountinfo()
	if err != nil {
		return nil, fmt.Errorf("The sandbox's mounts: %w", err)
	}
	for _, l := range lines {
		if l.id == stx.Mnt_id {
			m := &grantMount{id: l.id, dev: l.dev, root: l.root, tree: tree}
			for _, o := range l.optional {
				if g, ok := strings.CutPrefix(o, "shared:"); ok {
					m.group = g
				}
			}
			return m, nil
		}
	}
	return nil, fmt.Errorf("The grant's mount (%d) isn't in the sandbox's mount namespace", stx.Mnt_id)
}

// copyOf reports whether l is the grant's mount, or one propagated from it: in its peer group or its slave
func (m *grantMount) copyOf(l mountLine) bool {
	if l.id == m.id {
		return true
	}
	return m.group != "" && slices.ContainsFunc(l.optional, func(o string) bool {
		return o == "shared:"+m.group || o == "master:"+m.group
	})
}

// grantMounts maps each mount namespace in the sandbox (by inode) to the ids of the grant's mounts there: the mount
// itself and those propagated from it, whatever their paths. Read once per namespace, any thread's, before detaching
func (s *sandbox) grantMounts(m *grantMount) map[uint64]map[uint64]bool {
	byNs := map[uint64]map[uint64]bool{}
	for _, pid := range s.members() {
		for _, task := range tasks(pid) {
			ns, ok := mntNs(task)
			if !ok {
				continue
			}
			if _, seen := byNs[ns]; seen {
				continue
			}
			set := map[uint64]bool{}
			for _, l := range readMountinfo(task + "/mountinfo") {
				if m.copyOf(l) {
					set[l.id] = true
				}
			}
			byNs[ns] = set
		}
	}
	return byNs
}

// holdersAfter lists, after the detach, the processes in the sandbox still holding the grant: files, mappings, a
// working directory or root on its mounts (by mount id, which an open file keeps), or a mount of their own of the same
// filesystem and root, which a process can make in a mount namespace of its own and the detach doesn't reach. Every
// thread counts. Best effort: an fd in flight in an SCM_RIGHTS message or registered with io_uring shows nowhere in
// /proc, and keeps the grant readable until it's closed or the sandbox ends
func (s *sandbox) holdersAfter(ids map[uint64]map[uint64]bool, dev, root string) []holder {
	deadline := time.Now().Add(holdersTimeout)
	var hs []holder
	rebinds := map[uint64]bool{}
	for _, pid := range s.members() {
		if time.Now().After(deadline) {
			slog.Warn("Holders' scan cut short", "after", holdersTimeout)
			break
		}
		held := false
		for _, task := range tasks(pid) {
			ns, ok := mntNs(task)
			if !ok {
				continue
			}
			held = holdsMount(task, ids[ns])
			if !held && dev != "" {
				if _, checked := rebinds[ns]; !checked {
					rebinds[ns] = mountsOf(readMountinfo(task+"/mountinfo"), dev, root)
				}
				held = rebinds[ns]
			}
			if held {
				break
			}
		}
		if !held {
			held = holdsMapping(pid, ids)
		}
		if held {
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			if start, ok := startTime(pid); ok {
				hs = append(hs, holder{Pid: pid, Comm: strings.TrimSpace(string(comm)), Start: start})
			}
		}
	}
	return hs
}

// mntNs is the mount namespace of the task or process at dir in /proc, by inode
func mntNs(dir string) (uint64, bool) {
	var st unix.Stat_t
	if unix.Stat(dir+"/ns/mnt", &st) != nil {
		return 0, false
	}
	return st.Ino, true
}

// onMount reports whether path (a magic link in /proc) leads to one of the mounts
func onMount(path string, ids map[uint64]bool) bool {
	var stx unix.Statx_t
	return unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stx) == nil && ids[stx.Mnt_id]
}

// holdsMount reports whether the thread at task (its /proc directory) has its working directory, root or an open
// file on one of the mounts
func holdsMount(task string, ids map[uint64]bool) bool {
	if len(ids) == 0 {
		return false
	}
	if onMount(task+"/cwd", ids) || onMount(task+"/root", ids) {
		return true
	}
	entries, _ := os.ReadDir(task + "/fd")
	for _, e := range entries {
		if onMount(task+"/fd/"+e.Name(), ids) {
			return true
		}
	}
	return false
}

// holdsMapping reports whether pid maps a file on one of the grant's mounts, in any namespace: its threads share
// their mappings
func holdsMapping(pid int, ids map[uint64]map[uint64]bool) bool {
	all := map[uint64]bool{}
	for _, set := range ids {
		for id := range set {
			all[id] = true
		}
	}
	entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/map_files", pid))
	for _, e := range entries {
		if onMount(fmt.Sprintf("/proc/%d/map_files/%s", pid, e.Name()), all) {
			return true
		}
	}
	return false
}

// mountsOf reports whether there is a mount of the filesystem dev (major:minor) whose root is root or beneath it
func mountsOf(lines []mountLine, dev, root string) bool {
	for _, l := range lines {
		if l.dev == dev && (l.root == root || strings.HasPrefix(l.root, strings.TrimSuffix(root, "/")+"/")) {
			return true
		}
	}
	return false
}

// isShared reports whether dir is a shared mount in the sandbox's mount namespace: a daemon started again finds the
// grant directory shared by the one before
func (s *sandbox) isShared(dir string) bool {
	lines, err := s.mountinfo()
	if err != nil {
		return false
	}
	for _, l := range lines {
		if l.point == dir && slices.ContainsFunc(l.optional, func(o string) bool { return strings.HasPrefix(o, "shared:") }) {
			return true
		}
	}
	return false
}
