package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/orbit-online/agent-sandbox/internal/proc"
)

// The running sandbox: the outer bwrap's child, which nixpak's bwrapinfo.json names, in M1
type sandbox struct {
	pid   int
	pidfd int
}

var childPidRe = regexp.MustCompile(`"child-pid":\s*(\d+)`)

// findSandbox waits up to a minute for the launcher's sandbox, found as claude-desktop.sh's sandbox_pid finds it: the
// nixpak instance whose info names appID, and whose child-pid is in a mount namespace other than ours
func findSandbox(appID string) (*sandbox, error) {
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	for range 300 {
		if sb, err := lookupSandbox(runtime, appID); err == nil {
			return sb, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("No running sandbox for %s", appID)
}

func lookupSandbox(runtime, appID string) (*sandbox, error) {
	dirs, _ := filepath.Glob(filepath.Join(runtime, ".flatpak", "nixpak-app-*"))
	for _, d := range dirs {
		info, err := os.ReadFile(filepath.Join(d, "info"))
		if err != nil || !bytes.Contains(append([]byte("\n"), info...), []byte("\nname="+appID+"\n")) {
			continue
		}
		pid, err := childPid(filepath.Join(d, "bwrapinfo.json"))
		if err != nil || sameNs(pid, "mnt") {
			continue
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		// The pid could have been reused between reading the file and opening it
		if again, err := childPid(filepath.Join(d, "bwrapinfo.json")); err != nil || again != pid || sameNs(pid, "mnt") {
			unix.Close(fd)
			continue
		}
		return &sandbox{pid: pid, pidfd: fd}, nil
	}
	return nil, errors.New("Not running")
}

func childPid(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	m := childPidRe.FindSubmatch(data)
	if m == nil {
		return 0, fmt.Errorf("No child-pid in %s", path)
	}
	return strconv.Atoi(string(m[1]))
}

// sameNs reports whether pid is in our namespace of the kind (mnt, user), false when it can't tell
func sameNs(pid int, kind string) bool {
	var a, b unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), &a) != nil || unix.Stat("/proc/self/ns/"+kind, &b) != nil {
		return false
	}
	return a.Ino == b.Ino && a.Dev == b.Dev
}

// sameNsAs reports whether two processes share the namespace of the kind
func sameNsAs(a, b int, kind string) bool {
	var sa, sb unix.Stat_t
	if unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", a, kind), &sa) != nil ||
		unix.Stat(fmt.Sprintf("/proc/%d/ns/%s", b, kind), &sb) != nil {
		return false
	}
	return sa.Ino == sb.Ino && sa.Dev == sb.Dev
}

// alive reports whether the sandbox still runs: a pidfd turns readable when its process exits
func (s *sandbox) alive() bool { return proc.Alive(s.pidfd) }

// share makes path a shared mount in the sandbox's mount namespace, through nsenter in the user namespace that owns
// it: the Go runtime is multithreaded and can't setns into a user namespace. nsenter keeps our ids (becoming uid 0
// would need setgroups, which a user namespace may deny) and passes the capabilities setns granted through the exec
func (s *sandbox) share(path string) error {
	mnt, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", s.pid))
	if err != nil {
		return fmt.Errorf("Open the sandbox's mount namespace: %w", err)
	}
	defer mnt.Close()
	if !s.alive() {
		return errors.New("The sandbox ended")
	}
	ownerFd, err := unix.IoctlRetInt(int(mnt.Fd()), unix.NS_GET_USERNS)
	if err != nil {
		return fmt.Errorf("Find the owner of the sandbox's mount namespace: %w", err)
	}
	owner := os.NewFile(uintptr(ownerFd), "userns")
	defer owner.Close()
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("Find own executable: %w", err)
	}
	cmd := exec.Command(nsenter, "--user=/proc/self/fd/3", "--mount=/proc/self/fd/4", "--preserve-credentials",
		"--keep-caps", "--", self, "make-shared", path)
	cmd.ExtraFiles = []*os.File{owner, mnt}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("Make %s shared: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

// A Claude Code session, as far as the sandbox can be believed: anything in it can set the variable, so this only
// serves leases and bookkeeping
type session struct {
	id     string
	anchor int // the claude process, by our pid
	pidfd  int
}

// Claude Code's binary, by the name of /proc/<pid>/exe
var claudeExe = "claude"

// sessionOf walks pid's ancestors up to top (the sandbox's pid, so never into the host) to the first with
// CLAUDE_CODE_SESSION_ID in its environment, and takes that one's parent as the session's anchor if it runs Claude
// Code, is below top and isn't a pid namespace's init (a double fork would make it one). Returns nil without an error
// when the caller has no session
func sessionOf(pid, top int) (*session, error) {
	for p := pid; p > 1 && p != top; {
		id := environ(p)["CLAUDE_CODE_SESSION_ID"]
		ppid, _, err := parent(p)
		if err != nil {
			return nil, err
		}
		if id == "" {
			p = ppid
			continue
		}
		if _, anchorInit, err := parent(ppid); err != nil || anchorInit || ppid == top || ppid <= 1 {
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
