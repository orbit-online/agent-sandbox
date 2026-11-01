package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

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

// An attach grant's mount in M1, found when it's attached by the tree's mount id, not by its path: the sandbox can
// rename the grant directory in M1 (models/README.md, Attacker 6). Its id, peer group, and device and root, by which
// copies of it are found; the tree itself, which the daemon keeps open, and its device as stat gives it
type grantMount struct {
	id        uint64
	group     string
	dev, root string
	tree      *os.File
	srcDev    uint64
}

// grantMountOf finds the mount the tree (attached in M1) is in M1's mountinfo, by its mount id
func (s *sandbox) grantMountOf(tree *os.File) (*grantMount, error) {
	var stx unix.Statx_t
	if err := unix.Statx(int(tree.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil ||
		stx.Mask&unix.STATX_MNT_ID == 0 {
		return nil, fmt.Errorf("The grant's mount id: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(tree.Fd()), &st); err != nil {
		return nil, err
	}
	lines, err := s.mountinfo()
	if err != nil {
		return nil, fmt.Errorf("The sandbox's mounts: %w", err)
	}
	for _, l := range lines {
		if l.id == stx.Mnt_id {
			m := &grantMount{id: l.id, dev: l.dev, root: l.root, tree: tree, srcDev: st.Dev}
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
