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
	for _, pid := range s.members() {
		ns, ok := mntNs(pid)
		if !ok {
			continue
		}
		if _, seen := byNs[ns]; seen {
			continue
		}
		set := map[uint64]bool{}
		for _, l := range readMountinfo(fmt.Sprintf("/proc/%d/mountinfo", pid)) {
			if l.point == mountpoint || strings.HasPrefix(l.point, mountpoint+"/") {
				set[l.id] = true
			}
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
	for _, pid := range s.members() {
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
				rebinds[ns] = mountsOf(readMountinfo(fmt.Sprintf("/proc/%d/mountinfo", pid)), dev, root)
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

// mountsOf reports whether there is a mount of the filesystem dev (major:minor) whose root is root or beneath it
func mountsOf(lines []mountLine, dev, root string) bool {
	for _, l := range lines {
		if l.dev == dev && (l.root == root || strings.HasPrefix(l.root, strings.TrimSuffix(root, "/")+"/")) {
			return true
		}
	}
	return false
}

// mountOf finds the device and root of the mount at mountpoint, the last one there
func mountOf(lines []mountLine, mountpoint string) (dev, root string) {
	for _, l := range lines {
		if l.point == mountpoint {
			dev, root = l.dev, l.root
		}
	}
	return dev, root
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
