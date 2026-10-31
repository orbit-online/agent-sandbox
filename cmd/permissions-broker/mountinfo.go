package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// mountsBelow lists the mount points strictly below dir in a mountinfo file, deepest first
func mountsBelow(mountinfo, dir string) ([]string, error) {
	ids, err := mountIDs(mountinfo, func(p string) bool { return strings.HasPrefix(p, dir+"/") })
	if err != nil {
		return nil, err
	}
	var points []string
	for _, p := range ids {
		points = append(points, p)
	}
	sort.Slice(points, func(i, j int) bool { return len(points[i]) > len(points[j]) })
	return points, nil
}

// mountIDs maps the ids of the mounts in a mountinfo file whose mount point matches to the mount point
func mountIDs(mountinfo string, match func(string) bool) (map[int]string, error) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ids := map[int]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		point := unescapeMountinfo(fields[4])
		if match(point) {
			id, _ := strconv.Atoi(fields[0])
			ids[id] = point
		}
	}
	return ids, sc.Err()
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

// A process in the sandbox holding files, mappings, its working directory or a mount of its own of a grant
type holder struct {
	Pid  int    `json:"pid"`
	Comm string `json:"comm"`
}

// How long the holders' scan may take: the sandbox decides how many processes and files there are
var holdersTimeout = 10 * time.Second

// grantMounts maps each mount namespace in the sandbox (by inode) to the ids of the grant's mounts there: those at or
// below its mount point. Read once per namespace, before detaching, while the mount points still resolve
func (s *sandbox) grantMounts(mountpoint string) map[uint64]map[uint64]bool {
	byNs := map[uint64]map[uint64]bool{}
	for _, pid := range append([]int{s.pid}, descendants(s.pid)...) {
		ns, ok := mntNs(pid)
		if !ok {
			continue
		}
		if _, seen := byNs[ns]; seen {
			continue
		}
		ids, _ := mountIDs(fmt.Sprintf("/proc/%d/mountinfo", pid), func(p string) bool {
			return p == mountpoint || strings.HasPrefix(p, mountpoint+"/")
		})
		set := map[uint64]bool{}
		for id := range ids {
			set[uint64(id)] = true
		}
		byNs[ns] = set
	}
	return byNs
}

// holdersAfter lists, after the detach, the processes in the sandbox still holding the grant: files, mappings or a
// working directory on its mounts (by mount id, which an open file keeps), or a mount of their own of the same
// filesystem and root, which a process can make in a mount namespace of its own and the detach doesn't reach
func (s *sandbox) holdersAfter(ids map[uint64]map[uint64]bool, dev, root string) []holder {
	deadline := time.Now().Add(holdersTimeout)
	var hs []holder
	rebinds := map[uint64]bool{}
	for _, pid := range descendants(s.pid) {
		if time.Now().After(deadline) {
			slog.Warn("Holders' scan cut short", "after", holdersTimeout)
			break
		}
		ns, ok := mntNs(pid)
		if !ok {
			continue
		}
		held := holdsMount(pid, ids[ns])
		if !held && dev != "" {
			if _, checked := rebinds[ns]; !checked {
				rebinds[ns] = mountsOf(fmt.Sprintf("/proc/%d/mountinfo", pid), dev, root)
			}
			held = rebinds[ns]
		}
		if held {
			comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
			hs = append(hs, holder{Pid: pid, Comm: strings.TrimSpace(string(comm))})
		}
	}
	return hs
}

func mntNs(pid int) (uint64, bool) {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &st) != nil {
		return 0, false
	}
	return st.Ino, true
}

// holdsMount reports whether pid's working directory, an open file or a mapping is on one of the mounts
func holdsMount(pid int, ids map[uint64]bool) bool {
	if len(ids) == 0 {
		return false
	}
	on := func(path string) bool {
		var stx unix.Statx_t
		return unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_MNT_ID, &stx) == nil && ids[stx.Mnt_id]
	}
	if on(fmt.Sprintf("/proc/%d/cwd", pid)) {
		return true
	}
	for _, dir := range []string{"fd", "map_files"} {
		entries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/%s", pid, dir))
		for _, e := range entries {
			if on(fmt.Sprintf("/proc/%d/%s/%s", pid, dir, e.Name())) {
				return true
			}
		}
	}
	return false
}

// mountsOf reports whether a mountinfo file has a mount of the filesystem dev (major:minor) whose root is root or
// beneath it
func mountsOf(mountinfo, dev, root string) bool {
	f, err := os.Open(mountinfo)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[2] != dev {
			continue
		}
		r := unescapeMountinfo(fields[3])
		if r == root || strings.HasPrefix(r, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// mountOf finds the device and root of the mount at mountpoint in a mountinfo file
func mountOf(mountinfo, mountpoint string) (dev, root string) {
	f, err := os.Open(mountinfo)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 5 && unescapeMountinfo(fields[4]) == mountpoint {
			dev, root = fields[2], unescapeMountinfo(fields[3])
		}
	}
	return dev, root
}

// descendants lists pid's descendants, through every thread's children
func descendants(pid int) []int {
	var out []int
	queue := []int{pid}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", p))
		for _, t := range tasks {
			data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/task/%s/children", p, t.Name()))
			for _, c := range strings.Fields(string(data)) {
				if n, err := strconv.Atoi(c); err == nil {
					out = append(out, n)
					queue = append(queue, n)
				}
			}
		}
	}
	return out
}

// isDescendant reports whether pid is below the sandbox's pid
func (s *sandbox) isDescendant(pid int) bool {
	for p := pid; p > 1; {
		ppid, _, err := parent(p)
		if err != nil {
			return false
		}
		if ppid == s.pid {
			return true
		}
		p = ppid
	}
	return false
}

// isShared reports whether dir is a shared mount in the sandbox's mount namespace: a daemon started again finds the
// grant directory shared by the one before
func (s *sandbox) isShared(dir string) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", s.pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 7 || unescapeMountinfo(fields[4]) != dir {
			continue
		}
		for _, opt := range fields[6:] {
			if opt == "-" {
				break
			}
			if strings.HasPrefix(opt, "shared:") {
				return true
			}
		}
	}
	return false
}
