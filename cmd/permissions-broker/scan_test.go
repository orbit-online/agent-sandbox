package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

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
