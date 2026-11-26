package mounts

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The scan's deadline holds inside one process and one mountinfo file: past it, no further file of a process is
// looked at and no further mount read, however many threads, open files and mounts the sandbox gave them
func TestScanDeadline(t *testing.T) {
	f, err := os.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var stx unix.Statx_t
	if err := unix.Statx(int(f.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil {
		t.Fatal(err)
	}
	view := func(deadline time.Time) *mountView {
		return &mountView{m: &GrantMount{}, deadline: deadline, visible: map[uint64]bool{},
			copies: map[uint64]bool{stx.Mnt_id: true}, rebinds: map[uint64]bool{}, unsure: map[uint64]bool{},
			tried: map[string]bool{}}
	}
	if held, _ := view(time.Now().Add(time.Hour)).holds(os.Getpid()); !held {
		t.Fatal("A process with an open file on the grant's mount isn't a holder")
	}
	if held, possible := view(time.Now().Add(-time.Second)).holds(os.Getpid()); held || possible {
		t.Errorf("Past the deadline the scan still looked at the process's files: held %v, possible %v", held, possible)
	}
	if lines := readMounts("/proc/self/mountinfo", time.Now().Add(time.Hour)); len(lines) == 0 {
		t.Fatal("No mounts read")
	}
	if lines := readMounts("/proc/self/mountinfo", time.Now().Add(-time.Second)); len(lines) != 0 {
		t.Errorf("Past the deadline %d mounts were still read", len(lines))
	}
}

// A maps line: the device in hex, a path with spaces kept, a deleted file's marker kept, none for an anonymous one
func TestParseMapsLine(t *testing.T) {
	for _, c := range []struct {
		line, path string
		dev, ino   uint64
	}{
		{"7286768a7000-7286768a8000 rw-s 00000000 fe:01 19179613                   /sub/a file", "/sub/a file",
			unix.Mkdev(0xfe, 1), 19179613},
		{"7f00-7f01 r--p 00000000 00:2a 42  /x (deleted)", "/x (deleted)", unix.Mkdev(0, 0x2a), 42},
		{"7ffd-7ffe rw-p 00000000 00:00 0 ", "", 0, 0},
	} {
		dev, ino, path, ok := parseMapsLine(c.line)
		if !ok || dev != c.dev || ino != c.ino || path != c.path {
			t.Errorf("%q: %d %d %q %v", c.line, dev, ino, path, ok)
		}
	}
	if _, _, _, ok := parseMapsLine("garbage"); ok {
		t.Error("Parsed garbage")
	}
	if got := parseDev("254:1"); got != unix.Mkdev(254, 1) {
		t.Errorf("parseDev: %d", got)
	}
}
