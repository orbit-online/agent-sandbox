// Package proc reads what the kernel tells about processes
package proc

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PidOf returns the pid behind pidfd, in our pid namespace, from the pidfd's fdinfo
func PidOf(pidfd int) (int, error) {
	f, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(pidfd))
	if err != nil {
		return 0, fmt.Errorf("Read pidfd info: %w", err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "Pid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || pid <= 0 {
				return 0, fmt.Errorf("Process has exited or is outside the broker's pid namespace")
			}
			return pid, nil
		}
	}
	return 0, fmt.Errorf("No pid in pidfd info")
}

// Alive reports whether a pidfd's process still runs: a pidfd turns readable when it exits. A poll a signal interrupts
// (Go's runtime sends them to preempt goroutines) is no answer, so it's asked again
func Alive(pidfd int) bool {
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if err != unix.EINTR {
			return n == 0
		}
	}
}
