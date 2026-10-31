package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// A Claude Code session, as far as the sandbox can be believed: anything in it can set the variable, so this only
// serves leases and bookkeeping
type session struct {
	id     string
	anchor int // the claude process, by our pid
	pidfd  int
}

// Claude Code's binary, by the name of /proc/<pid>/exe
var claudeExe = "claude"

// sessionOf walks pid's ancestors to the first with CLAUDE_CODE_SESSION_ID in its environment, and takes that one's
// parent as the session's anchor if it runs Claude Code, is in the sandbox, isn't the sandbox's pid and isn't a pid
// namespace's init (a double fork would make it one). The walk stops at the sandbox's boundary, never reading a
// process outside it: a re-entry (claude-desktop --shell) is a child of nsenter on the host, not of the sandbox's pid,
// and above that may be a host Claude Code session's shell. Returns nil without an error when the caller has no session
func (s *sandbox) sessionOf(pid int) (*session, error) {
	top := s.pid
	for p := pid; p > 1 && p != top && s.contains(p); {
		id := environ(p)["CLAUDE_CODE_SESSION_ID"]
		ppid, _, err := parent(p)
		if err != nil {
			return nil, err
		}
		if id == "" {
			p = ppid
			continue
		}
		if _, anchorInit, err := parent(ppid); err != nil || anchorInit || ppid == top || ppid <= 1 || !s.contains(ppid) {
			return nil, nil
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", ppid))
		if err != nil || filepath.Base(exe) != claudeExe {
			return nil, nil
		}
		fd, err := unix.PidfdOpen(ppid, 0)
		if err != nil {
			return nil, nil
		}
		// The anchor could have exited and its pid been reused since: it must still be p's parent
		if again, _, err := parent(p); err != nil || again != ppid {
			unix.Close(fd)
			return nil, nil
		}
		return &session{id: id, anchor: ppid, pidfd: fd}, nil
	}
	return nil, nil
}

func environ(pid int) map[string]string {
	data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	env := map[string]string{}
	for _, kv := range bytes.Split(data, []byte{0}) {
		if k, v, ok := strings.Cut(string(kv), "="); ok {
			env[k] = v
		}
	}
	return env
}

// parent returns pid's parent and whether pid is the init of its pid namespace (its innermost NSpid is 1)
func parent(pid int) (int, bool, error) {
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
