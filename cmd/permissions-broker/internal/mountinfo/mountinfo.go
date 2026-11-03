// Package mountinfo reads mountinfo files (proc_pid_mountinfo(5))
package mountinfo

import (
	"bufio"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Line is a line of a mountinfo file: the mount's id, device (major:minor), root, mount point and optional fields
type Line struct {
	ID               uint64
	Dev, Root, Point string
	Optional         []string
}

// Parse reads a mountinfo file's lines
func Parse(r io.Reader) ([]Line, error) {
	var lines []Line
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 7 {
			continue
		}
		id, _ := strconv.ParseUint(f[0], 10, 64)
		l := Line{ID: id, Dev: f[2], Root: unescape(f[3]), Point: unescape(f[4])}
		for _, opt := range f[6:] {
			if opt == "-" {
				break
			}
			l.Optional = append(l.Optional, opt)
		}
		lines = append(lines, l)
	}
	return lines, sc.Err()
}

// Read parses a mountinfo file by path, nil when it can't be read
func Read(path string) []Line {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	lines, _ := Parse(f)
	return lines
}

// Below lists the mount points strictly below dir, deepest first
func Below(lines []Line, dir string) []string {
	var points []string
	for _, l := range lines {
		if strings.HasPrefix(l.Point, dir+"/") && !slices.Contains(points, l.Point) {
			points = append(points, l.Point)
		}
	}
	sort.Slice(points, func(i, j int) bool { return len(points[i]) > len(points[j]) })
	return points
}

// mountinfo escapes space, tab, newline and backslash as \ooo
func unescape(s string) string {
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

// MountsOf reports whether there is a mount of the filesystem dev (major:minor) whose root is root or beneath it
func MountsOf(lines []Line, dev, root string) bool {
	for _, l := range lines {
		if l.Dev == dev && (l.Root == root || strings.HasPrefix(l.Root, strings.TrimSuffix(root, "/")+"/")) {
			return true
		}
	}
	return false
}
