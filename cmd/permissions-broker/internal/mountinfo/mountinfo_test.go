package mountinfo

import (
	"strings"
	"testing"
)

// A line past MaxLine is cut, with its id and device kept, and the lines after it are read. One of exactly MaxLine
// is whole, and so is a last line without a newline
func TestParseLongLine(t *testing.T) {
	head := "36 35 98:0 /root "
	tail := " rw,noatime shared:7 master:1 - ext3 /dev/root rw"
	fit := "/" + strings.Repeat("p", MaxLine-len(head)-len(tail)-1)
	file := "21 20 0:5 / /first rw shared:1 - tmpfs tmpfs rw\n" +
		"22 20 0:6 /" + strings.Repeat("r", 2*MaxLine) + " /deep rw shared:2 - tmpfs tmpfs rw\n" +
		head + fit + tail + "\n" +
		"23 20 0:7 /sub /after\\040it rw master:3 - tmpfs tmpfs rw"
	lines, err := Parse(strings.NewReader(file))
	if err != nil || len(lines) != 4 {
		t.Fatalf("%d lines, %v", len(lines), err)
	}
	if l := lines[1]; !l.Cut || l.ID != 22 || l.Dev != "0:6" || l.Root != "" {
		t.Errorf("The long line: cut %v, id %d, dev %s, a root of %d", l.Cut, l.ID, l.Dev, len(l.Root))
	}
	if l := lines[2]; l.Cut || l.ID != 36 || l.Point != fit || len(l.Optional) != 2 {
		t.Errorf("The line of MaxLine: cut %v, id %d, a mount point of %d, %v", l.Cut, l.ID, len(l.Point), l.Optional)
	}
	if l := lines[3]; l.Cut || l.ID != 23 || l.Root != "/sub" || l.Point != "/after it" || l.Optional[0] != "master:3" {
		t.Errorf("The line after: %+v", l)
	}
}
