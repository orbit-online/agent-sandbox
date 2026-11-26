// Package mountinfo reads mountinfo files (proc_pid_mountinfo(5))
package mountinfo

import (
	"bufio"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Line is a line of a mountinfo file: the mount's id, device (major:minor), root, mount point, whether it's mounted
// read-only, and optional fields. Cut: the line was longer than a line is read (MaxLine), so only its id and device
// are known
type Line struct {
	ID               uint64
	Dev, Root, Point string
	RO               bool
	Optional         []string
	Cut              bool
}

// MaxLine is how much of a line EachLine reads. A path may be any length (a process walks into a directory deeper
// than PATH_MAX step by step), so a process picks how long its mounts' lines in mountinfo and its mappings' in maps are
const MaxLine = 1 << 20

// EachLine calls line for each line of r, a /proc file, until it returns false. A line past MaxLine is cut there and
// cut says so: what follows such a line is still read
func EachLine(r io.Reader, line func(text []byte, cut bool) bool) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var buf []byte
	cut := false
	for {
		part, err := br.ReadSlice('\n')
		if err == nil {
			part = part[:len(part)-1]
		}
		if room := MaxLine - len(buf); len(part) > room {
			part, cut = part[:room], true
		}
		buf = append(buf, part...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(buf) > 0 && !line(buf, cut) {
			return nil
		}
		buf, cut = buf[:0], false
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Each calls line for each mount of a mountinfo file, until it returns false: a file of the sandbox's has as many
// lines, as long, as the sandbox likes, so its reader keeps none of them
func Each(r io.Reader, line func(Line) bool) error {
	return EachLine(r, func(text []byte, cut bool) bool {
		f := strings.Fields(string(text))
		if len(f) < 7 && !(cut && len(f) >= 3) {
			return true
		}
		id, _ := strconv.ParseUint(f[0], 10, 64)
		if cut {
			// The id and the device come first; the root or the mount point is where it's cut
			return line(Line{ID: id, Dev: f[2], Cut: true})
		}
		l := Line{ID: id, Dev: f[2], Root: unescape(f[3]), Point: unescape(f[4]),
			RO: slices.Contains(strings.Split(f[5], ","), "ro")}
		for _, opt := range f[6:] {
			if opt == "-" {
				break
			}
			l.Optional = append(l.Optional, opt)
		}
		return line(l)
	})
}

// Parse reads a mountinfo file's lines
func Parse(r io.Reader) ([]Line, error) {
	var lines []Line
	err := Each(r, func(l Line) bool {
		lines = append(lines, l)
		return true
	})
	return lines, err
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
