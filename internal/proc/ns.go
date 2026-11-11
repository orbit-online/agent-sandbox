package proc

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// NsIno returns the inode of pid's namespace of kind, 0 when it can't be read
func NsIno(pid int, kind string) uint64 {
	var st unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &st) != nil {
		return 0
	}
	return st.Ino
}

// SameNs reports whether pid is in our namespace of kind
func SameNs(pid int, kind string) bool {
	var a, b unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &a) != nil || unix.Stat("/proc/self/ns/"+kind, &b) != nil {
		return false
	}
	return a.Ino == b.Ino && a.Dev == b.Dev
}

// Parent returns pid's parent and whether pid is the init of its pid namespace (its innermost NSpid is 1)
func Parent(pid int) (int, bool, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, false, fmt.Errorf("Read status of %d: %w", pid, err)
	}
	ppid, nsInit := 0, false
	for _, line := range strings.Split(string(data), "\n") {
		k, v, _ := strings.Cut(line, ":")
		f := strings.Fields(v)
		switch {
		case k == "PPid" && len(f) == 1:
			ppid, _ = strconv.Atoi(f[0])
		case k == "NSpid" && len(f) > 0:
			nsInit = f[len(f)-1] == "1"
		}
	}
	return ppid, nsInit, nil
}
